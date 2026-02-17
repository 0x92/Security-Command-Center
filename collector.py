#!/usr/bin/env python3
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import time
from datetime import datetime, timezone

DB_PATH = '/opt/security-monitor/data/security_events.db'
CURSOR_PATH = '/opt/security-monitor/data/journal.cursor'
OFFSETS_PATH = '/opt/security-monitor/data/file_offsets.json'
POLL_SECONDS = 5
RETENTION_DAYS = 30
MAX_RECENT_BOOTSTRAP = 1000

WEB_LOGS = [
    '/var/log/nginx/access.log',
    '/var/log/apache2/access.log',
]
FAIL2BAN_LOGS = [
    '/var/log/fail2ban.log',
]

RE_UFW = re.compile(r"\[UFW BLOCK\].*SRC=(?P<src>\S+).*DPT=(?P<dpt>\d+)")
RE_SSH_FAIL = re.compile(r"Failed password for(?: invalid user)? (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)")
RE_SSH_FAIL_KEY = re.compile(r"Failed publickey for(?: invalid user)? (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)")
RE_SSH_ACCEPT = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)")
RE_F2B_BAN = re.compile(r"\[sshd\]\s+Ban\s+(?P<ip>[0-9a-fA-F:.]+)")
RE_F2B_UNBAN = re.compile(r"\[sshd\]\s+Unban\s+(?P<ip>[0-9a-fA-F:.]+)")
RE_F2B_LOG = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}).*?\[sshd\]\s+(?P<verb>Ban|Unban)\s+(?P<ip>[0-9a-fA-F:.]+)"
)

# Combined log format for Nginx/Apache
RE_WEB = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>[^\s"]+) [^"]+" (?P<status>\d{3}) (?P<size>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)

try:
    from user_agents import parse as parse_user_agent
except Exception:
    parse_user_agent = None


class GeoResolver:
    def __init__(self):
        self.cache = {}

    def _is_private(self, ip):
        try:
            return ipaddress.ip_address(ip).is_private
        except Exception:
            return False

    def resolve(self, ip):
        if not ip:
            return ('--', 'Unknown')
        if ip in self.cache:
            return self.cache[ip]
        if self._is_private(ip):
            self.cache[ip] = ('PR', 'Private Network')
            return self.cache[ip]

        code = '--'
        name = 'Unknown'
        try:
            proc = subprocess.run(['geoiplookup', ip], capture_output=True, text=True, timeout=2, check=False)
            out = (proc.stdout or '').strip()
            # Example: "GeoIP Country Edition: US, United States"
            if ':' in out and ',' in out:
                payload = out.split(':', 1)[1].strip()
                cc = payload.split(',', 1)[0].strip()
                cn = payload.split(',', 1)[1].strip()
                if cc and cc != 'IP Address not found':
                    code = cc.upper()
                    name = cn
        except Exception:
            pass

        self.cache[ip] = (code, name)
        return self.cache[ip]


class UserAgentResolver:
    def __init__(self):
        self.cache = {}

    def resolve(self, ua_string):
        ua_string = (ua_string or '')[:512]
        if not ua_string:
            return ('-', '-')
        if ua_string in self.cache:
            return self.cache[ua_string]

        family = ua_string
        device = 'unknown'
        if parse_user_agent:
            try:
                ua = parse_user_agent(ua_string)
                family = f"{ua.browser.family} {ua.browser.version_string}".strip()
                if ua.is_bot:
                    device = 'bot'
                elif ua.is_mobile:
                    device = 'mobile'
                elif ua.is_tablet:
                    device = 'tablet'
                elif ua.is_pc:
                    device = 'desktop'
            except Exception:
                pass

        self.cache[ua_string] = (family[:120], device)
        return self.cache[ua_string]


def connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_db(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            source TEXT NOT NULL,
            category TEXT NOT NULL,
            action TEXT NOT NULL,
            ip TEXT,
            port INTEGER,
            raw TEXT NOT NULL,
            country_code TEXT,
            country_name TEXT,
            method TEXT,
            path TEXT,
            status INTEGER,
            user_agent TEXT,
            ua_family TEXT,
            ua_device TEXT
        )
        """
    )

    cols = {r['name'] for r in conn.execute('PRAGMA table_info(events)').fetchall()}
    needed = {
        'country_code': 'TEXT',
        'country_name': 'TEXT',
        'method': 'TEXT',
        'path': 'TEXT',
        'status': 'INTEGER',
        'user_agent': 'TEXT',
        'ua_family': 'TEXT',
        'ua_device': 'TEXT',
    }
    for col, ctype in needed.items():
        if col not in cols:
            conn.execute(f'ALTER TABLE events ADD COLUMN {col} {ctype}')

    conn.execute('CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_events_cat ON events(category)')
    conn.commit()


def load_text(path):
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            return f.read().strip()
    return ''


def save_text(path, value):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(value)
    os.replace(tmp, path)


def load_json(path):
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            try:
                return json.load(f)
            except Exception:
                return {}
    return {}


def save_json(path, data):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f)
    os.replace(tmp, path)


def run_journal(cursor):
    cmd = ['journalctl', '--no-pager', '-o', 'json']
    if cursor:
        cmd.extend(['--after-cursor', cursor])
    else:
        cmd.extend(['-n', str(MAX_RECENT_BOOTSTRAP)])
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode not in (0, 1):
        return []
    records = []
    for ln in proc.stdout.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            records.append(json.loads(ln))
        except Exception:
            continue
    return records


def insert_event(conn, event):
    conn.execute(
        """
        INSERT INTO events(
            ts, source, category, action, ip, port, raw,
            country_code, country_name, method, path, status,
            user_agent, ua_family, ua_device
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            event.get('ts'), event.get('source'), event.get('category'), event.get('action'), event.get('ip'), event.get('port'), event.get('raw', '')[:1000],
            event.get('country_code'), event.get('country_name'), event.get('method'), event.get('path'), event.get('status'),
            event.get('user_agent'), event.get('ua_family'), event.get('ua_device')
        )
    )


def parse_journal_record(rec):
    msg = rec.get('MESSAGE', '')
    ident = rec.get('SYSLOG_IDENTIFIER', '')

    if '[UFW BLOCK]' in msg:
        m = RE_UFW.search(msg)
        return {
            'source': 'ufw', 'category': 'attack', 'action': 'ufw_block',
            'ip': m.group('src') if m else None,
            'port': int(m.group('dpt')) if m else None,
            'raw': msg,
        }

    if ident == 'sshd' or 'sshd[' in msg:
        m_fail = RE_SSH_FAIL.search(msg) or RE_SSH_FAIL_KEY.search(msg)
        if m_fail:
            return {
                'source': 'sshd', 'category': 'attack', 'action': 'ssh_failed_login',
                'ip': m_fail.group('ip'), 'port': int(m_fail.group('port')), 'raw': msg,
            }
        m_accept = RE_SSH_ACCEPT.search(msg)
        if m_accept:
            return {
                'source': 'sshd', 'category': 'connection', 'action': 'ssh_accepted',
                'ip': m_accept.group('ip'), 'port': int(m_accept.group('port')), 'raw': msg,
            }

    if ident == 'fail2ban.actions' or 'fail2ban.actions' in msg:
        m_ban = RE_F2B_BAN.search(msg)
        if m_ban:
            return {
                'source': 'fail2ban', 'category': 'attack', 'action': 'ip_banned',
                'ip': m_ban.group('ip'), 'port': None, 'raw': msg,
            }
        m_unban = RE_F2B_UNBAN.search(msg)
        if m_unban:
            return {
                'source': 'fail2ban', 'category': 'info', 'action': 'ip_unbanned',
                'ip': m_unban.group('ip'), 'port': None, 'raw': msg,
            }

    return None


def parse_web_line(line, source):
    m = RE_WEB.search(line)
    if not m:
        return None

    status = int(m.group('status'))
    category = 'connection'
    action = 'http_request'
    if status >= 500:
        category = 'attack'
        action = 'http_5xx'
    elif status >= 400:
        category = 'attack'
        action = 'http_4xx'

    return {
        'source': source,
        'category': category,
        'action': action,
        'ip': m.group('ip'),
        'port': None,
        'raw': line,
        'method': m.group('method'),
        'path': m.group('path')[:240],
        'status': status,
        'user_agent': m.group('ua')[:512],
    }


def parse_fail2ban_line(line):
    m = RE_F2B_LOG.search(line or '')
    if not m:
        return None

    verb = (m.group('verb') or '').lower()
    action = 'ip_banned' if verb == 'ban' else 'ip_unbanned'
    category = 'attack' if action == 'ip_banned' else 'info'

    ts = datetime.now(timezone.utc).isoformat()
    try:
        dt = datetime.strptime(m.group('ts'), '%Y-%m-%d %H:%M:%S,%f')
        ts = dt.replace(tzinfo=timezone.utc).isoformat()
    except Exception:
        pass

    return {
        'source': 'fail2ban',
        'category': category,
        'action': action,
        'ip': m.group('ip'),
        'port': None,
        'raw': line[:1000],
        'ts': ts,
        'method': None,
        'path': None,
        'status': None,
        'user_agent': None,
        'ua_family': None,
        'ua_device': None,
    }


def process_web_logs(conn, offsets, geo, ua_resolver):
    changed = False
    for path in WEB_LOGS:
        if not os.path.exists(path):
            continue
        source = 'nginx' if 'nginx' in path else 'apache'
        try:
            current_size = os.path.getsize(path)
            offset = int(offsets.get(path, 0))
            if offset > current_size:
                offset = 0

            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                f.seek(offset)
                for line in f:
                    line = line.rstrip('\n')
                    event = parse_web_line(line, source)
                    if not event:
                        continue
                    cc, cn = geo.resolve(event.get('ip'))
                    family, device = ua_resolver.resolve(event.get('user_agent'))
                    event.update({
                        'ts': datetime.now(timezone.utc).isoformat(),
                        'country_code': cc,
                        'country_name': cn,
                        'ua_family': family,
                        'ua_device': device,
                    })
                    insert_event(conn, event)
                    changed = True
                offsets[path] = f.tell()
        except Exception:
            continue
    return changed


def process_fail2ban_logs(conn, offsets, geo):
    changed = False
    for path in FAIL2BAN_LOGS:
        if not os.path.exists(path):
            continue
        try:
            current_size = os.path.getsize(path)
            offset = int(offsets.get(path, 0))
            if offset > current_size:
                offset = 0

            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                f.seek(offset)
                for line in f:
                    line = line.rstrip('\n')
                    event = parse_fail2ban_line(line)
                    if not event:
                        continue
                    cc, cn = geo.resolve(event.get('ip'))
                    event.update({
                        'country_code': cc,
                        'country_name': cn,
                    })
                    insert_event(conn, event)
                    changed = True
                offsets[path] = f.tell()
        except Exception:
            continue
    return changed


def process_journal(conn, cursor, geo):
    changed = False
    records = run_journal(cursor)
    for rec in records:
        cursor = rec.get('__CURSOR', cursor)
        event = parse_journal_record(rec)
        if not event:
            continue

        ts_us = rec.get('__REALTIME_TIMESTAMP')
        if ts_us:
            ts = datetime.fromtimestamp(int(ts_us) / 1_000_000, tz=timezone.utc).isoformat()
        else:
            ts = datetime.now(timezone.utc).isoformat()

        cc, cn = geo.resolve(event.get('ip'))
        event.update({
            'ts': ts,
            'country_code': cc,
            'country_name': cn,
            'method': None,
            'path': None,
            'status': None,
            'user_agent': None,
            'ua_family': None,
            'ua_device': None,
        })
        insert_event(conn, event)
        changed = True

    return cursor, changed


def cleanup(conn):
    cutoff_ts = datetime.now(timezone.utc).timestamp() - (RETENTION_DAYS * 86400)
    cutoff_iso = datetime.fromtimestamp(cutoff_ts, tz=timezone.utc).isoformat()
    conn.execute('DELETE FROM events WHERE ts < ?', (cutoff_iso,))
    conn.commit()


def main():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = connect_db()
    ensure_db(conn)

    cursor = load_text(CURSOR_PATH)
    offsets = load_json(OFFSETS_PATH)

    geo = GeoResolver()
    ua_resolver = UserAgentResolver()

    last_cleanup = 0

    while True:
        changed = False

        cursor, journal_changed = process_journal(conn, cursor, geo)
        changed = changed or journal_changed

        web_changed = process_web_logs(conn, offsets, geo, ua_resolver)
        changed = changed or web_changed

        fail2ban_changed = process_fail2ban_logs(conn, offsets, geo)
        changed = changed or fail2ban_changed

        if changed:
            conn.commit()
        if cursor:
            save_text(CURSOR_PATH, cursor)
        save_json(OFFSETS_PATH, offsets)

        now = time.time()
        if now - last_cleanup >= 3600:
            cleanup(conn)
            last_cleanup = now

        time.sleep(POLL_SECONDS)


if __name__ == '__main__':
    main()
