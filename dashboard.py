#!/usr/bin/env python3
import ipaddress
import json
import os
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from flask import Flask, Response, jsonify, render_template, request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.getenv('SC_DATA_DIR', os.path.join(BASE_DIR, 'data'))
DB_PATH = os.getenv('SC_DB_PATH', os.path.join(DATA_DIR, 'security_events.db'))

ENRICH_TTL_SECONDS = 24 * 3600
THREAT_TTL_SECONDS = 6 * 3600
REMOTE_ENRICH_BUDGET = 6
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '').strip()
MAP_TARGET_NAME = os.getenv('MAP_TARGET_NAME', 'Protected Server')
MAP_TARGET_LAT = float(os.getenv('MAP_TARGET_LAT', '50.1109'))
MAP_TARGET_LON = float(os.getenv('MAP_TARGET_LON', '8.6821'))

LOCAL_IOC_CIDRS = [
    '198.51.100.0/24',
    '203.0.113.0/24',
    '192.0.2.0/24',
]

SPAMHAUS_DROP_URL = 'https://www.spamhaus.org/drop/drop.txt'

app = Flask(__name__)
_lock = threading.Lock()
_drop_cache = {'loaded_at': 0.0, 'cidrs': []}


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_support_tables():
    conn = get_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ip_enrichment (
            ip TEXT PRIMARY KEY,
            country_code TEXT,
            country_name TEXT,
            asn TEXT,
            as_org TEXT,
            threat_score INTEGER,
            threat_labels TEXT,
            abuse_confidence INTEGER,
            total_reports INTEGER,
            last_checked INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute('CREATE INDEX IF NOT EXISTS idx_ip_enrichment_updated ON ip_enrichment(updated_at)')
    cols = {r['name'] for r in conn.execute('PRAGMA table_info(ip_enrichment)').fetchall()}
    if 'lat' not in cols:
        conn.execute('ALTER TABLE ip_enrichment ADD COLUMN lat REAL')
    if 'lon' not in cols:
        conn.execute('ALTER TABLE ip_enrichment ADD COLUMN lon REAL')
    conn.commit()
    conn.close()


def q(sql, params=()):
    conn = get_conn()
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def window_start(hours):
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


def parse_ip(value):
    try:
        return ipaddress.ip_address((value or '').strip())
    except Exception:
        return None


def is_private_like(ip_obj):
    return bool(
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def to_iso_now():
    return datetime.now(timezone.utc).isoformat()


def fetch_json(url, headers=None, timeout=2.5):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode('utf-8', errors='replace'))


def load_drop_cidrs():
    now = time.time()
    with _lock:
        if now - _drop_cache['loaded_at'] < THREAT_TTL_SECONDS and _drop_cache['cidrs']:
            return _drop_cache['cidrs']

    cidrs = []
    for raw in LOCAL_IOC_CIDRS:
        try:
            cidrs.append(ipaddress.ip_network(raw, strict=False))
        except Exception:
            continue

    try:
        with urllib.request.urlopen(SPAMHAUS_DROP_URL, timeout=3) as resp:
            body = resp.read().decode('utf-8', errors='replace')
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith(';'):
                continue
            network = line.split(';', 1)[0].strip()
            if not network:
                continue
            try:
                cidrs.append(ipaddress.ip_network(network, strict=False))
            except Exception:
                continue
    except Exception:
        pass

    with _lock:
        _drop_cache['loaded_at'] = now
        _drop_cache['cidrs'] = cidrs
    return cidrs


def ip_in_ioc(ip_obj):
    labels = []
    score = 0

    for net in load_drop_cidrs():
        if ip_obj in net:
            labels.append('ioc_network_match')
            score = max(score, 90)
            break

    return score, labels


def behavior_score(ip):
    rows = q(
        """
        SELECT
          COUNT(*) AS total,
          COALESCE(SUM(CASE WHEN category='attack' THEN 1 ELSE 0 END), 0) AS attacks,
          COALESCE(SUM(CASE WHEN action='ssh_failed_login' THEN 1 ELSE 0 END), 0) AS ssh_fails,
          COALESCE(SUM(CASE WHEN action='ip_banned' THEN 1 ELSE 0 END), 0) AS bans
        FROM events
        WHERE ip = ? AND ts >= ?
        """,
        (ip, window_start(24)),
    )
    if not rows:
        return 0, []

    total = int(rows[0]['total'] or 0)
    attacks = int(rows[0]['attacks'] or 0)
    ssh_fails = int(rows[0]['ssh_fails'] or 0)
    bans = int(rows[0]['bans'] or 0)

    labels = []
    score = 0
    if attacks >= 10:
        score = max(score, 45)
        labels.append('high_attack_volume_24h')
    if ssh_fails >= 5:
        score = max(score, 55)
        labels.append('ssh_bruteforce_pattern')
    if bans >= 1:
        score = max(score, 70)
        labels.append('already_banned')
    if total >= 30 and attacks >= (total * 0.6):
        score = max(score, 65)
        labels.append('attack_dominant_traffic')

    return score, labels


def abuseipdb_score(ip):
    if not ABUSEIPDB_API_KEY:
        return None

    params = urllib.parse.urlencode({'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': ''})
    url = f'https://api.abuseipdb.com/api/v2/check?{params}'
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}
    try:
        payload = fetch_json(url, headers=headers, timeout=3)
        data = payload.get('data', {})
        score = int(data.get('abuseConfidenceScore') or 0)
        reports = int(data.get('totalReports') or 0)
        return {'abuse_confidence': score, 'total_reports': reports}
    except Exception:
        return None


def ipwhois_lookup(ip):
    try:
        payload = fetch_json(f'https://ipwho.is/{urllib.parse.quote(ip)}', timeout=2.8)
    except (urllib.error.URLError, TimeoutError, ValueError):
        return {}
    except Exception:
        return {}

    if payload.get('success') is False:
        return {}

    connection = payload.get('connection') or {}
    asn_value = connection.get('asn')
    asn = f"AS{asn_value}" if asn_value else None
    return {
        'country_code': (payload.get('country_code') or '--').upper(),
        'country_name': payload.get('country') or 'Unknown',
        'asn': asn,
        'as_org': connection.get('org') or connection.get('isp') or 'Unknown ASN',
        'lat': payload.get('latitude'),
        'lon': payload.get('longitude'),
    }


def get_cached_enrichment(ip):
    rows = q(
        """
        SELECT ip, country_code, country_name, asn, as_org, threat_score, threat_labels,
               abuse_confidence, total_reports, last_checked, lat, lon
        FROM ip_enrichment
        WHERE ip = ?
        """,
        (ip,),
    )
    if not rows:
        return None

    row = rows[0]
    labels = []
    try:
        labels = json.loads(row.get('threat_labels') or '[]')
    except Exception:
        labels = []

    row['threat_labels'] = labels
    row['threat_score'] = int(row.get('threat_score') or 0)
    row['abuse_confidence'] = int(row.get('abuse_confidence') or 0)
    row['total_reports'] = int(row.get('total_reports') or 0)
    row['last_checked'] = int(row.get('last_checked') or 0)
    row['lat'] = float(row.get('lat')) if row.get('lat') is not None else None
    row['lon'] = float(row.get('lon')) if row.get('lon') is not None else None
    return row


def upsert_enrichment(record):
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO ip_enrichment(
            ip, country_code, country_name, asn, as_org,
            threat_score, threat_labels, abuse_confidence,
            total_reports, last_checked, updated_at, lat, lon
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(ip) DO UPDATE SET
            country_code=excluded.country_code,
            country_name=excluded.country_name,
            asn=excluded.asn,
            as_org=excluded.as_org,
            threat_score=excluded.threat_score,
            threat_labels=excluded.threat_labels,
            abuse_confidence=excluded.abuse_confidence,
            total_reports=excluded.total_reports,
            last_checked=excluded.last_checked,
            updated_at=excluded.updated_at,
            lat=excluded.lat,
            lon=excluded.lon
        """,
        (
            record['ip'], record.get('country_code') or '--', record.get('country_name') or 'Unknown',
            record.get('asn') or 'AS-UNK', record.get('as_org') or 'Unknown ASN',
            int(record.get('threat_score') or 0), json.dumps(record.get('threat_labels') or []),
            int(record.get('abuse_confidence') or 0), int(record.get('total_reports') or 0),
            int(record.get('last_checked') or int(time.time())), record.get('updated_at') or to_iso_now(),
            record.get('lat'), record.get('lon'),
        ),
    )
    conn.commit()
    conn.close()


def resolve_enrichment(ip, allow_remote=True):
    ip_obj = parse_ip(ip)
    if not ip_obj:
        return {
            'ip': ip,
            'country_code': '--',
            'country_name': 'Unknown',
            'asn': 'AS-UNK',
            'as_org': 'Unknown ASN',
            'threat_score': 0,
            'threat_labels': ['invalid_ip'],
            'abuse_confidence': 0,
            'total_reports': 0,
            'lat': None,
            'lon': None,
        }

    if is_private_like(ip_obj):
        return {
            'ip': ip,
            'country_code': 'PR',
            'country_name': 'Private Network',
            'asn': 'AS-PRIV',
            'as_org': 'Private Network',
            'threat_score': 0,
            'threat_labels': ['private_ip'],
            'abuse_confidence': 0,
            'total_reports': 0,
            'lat': None,
            'lon': None,
        }

    now = int(time.time())
    cached = get_cached_enrichment(ip)
    cached_has_coords = cached and (cached.get('lat') is not None and cached.get('lon') is not None)
    if cached and now - cached.get('last_checked', 0) < ENRICH_TTL_SECONDS and cached_has_coords:
        return cached
    if cached and now - cached.get('last_checked', 0) < ENRICH_TTL_SECONDS and not allow_remote:
        return cached
    if cached and not allow_remote:
        return cached

    existing = q(
        """
        SELECT COALESCE(MAX(country_code), '--') AS country_code,
               COALESCE(MAX(country_name), 'Unknown') AS country_name
        FROM events WHERE ip = ?
        """,
        (ip,),
    )
    base_country = existing[0] if existing else {'country_code': '--', 'country_name': 'Unknown'}

    who = ipwhois_lookup(ip) if allow_remote else {}
    ioc_score, ioc_labels = ip_in_ioc(ip_obj)
    behavior, behavior_labels = behavior_score(ip)

    abuse = abuseipdb_score(ip) if allow_remote else None
    abuse_conf = int((abuse or {}).get('abuse_confidence') or 0)
    total_reports = int((abuse or {}).get('total_reports') or 0)

    labels = []
    labels.extend(ioc_labels)
    labels.extend(behavior_labels)
    if abuse_conf >= 30:
        labels.append('abuseipdb_reported')

    threat = max(ioc_score, behavior, abuse_conf)

    record = {
        'ip': ip,
        'country_code': who.get('country_code') or base_country.get('country_code') or '--',
        'country_name': who.get('country_name') or base_country.get('country_name') or 'Unknown',
        'asn': who.get('asn') or (cached or {}).get('asn') or 'AS-UNK',
        'as_org': who.get('as_org') or (cached or {}).get('as_org') or 'Unknown ASN',
        'threat_score': threat,
        'threat_labels': sorted(set(labels)),
        'abuse_confidence': abuse_conf,
        'total_reports': total_reports,
        'lat': who.get('lat') if who.get('lat') is not None else (cached or {}).get('lat'),
        'lon': who.get('lon') if who.get('lon') is not None else (cached or {}).get('lon'),
        'last_checked': now,
        'updated_at': to_iso_now(),
    }

    upsert_enrichment(record)
    return record


def apply_enrichment(rows, max_remote=REMOTE_ENRICH_BUDGET):
    budget = max_remote
    out = []
    for row in rows:
        ip = row.get('ip')
        if not ip or ip in ('-', 'unknown'):
            row['asn'] = 'AS-UNK'
            row['as_org'] = 'Unknown ASN'
            row['threat_score'] = 0
            row['threat_labels'] = []
            row['abuse_confidence'] = 0
            row['total_reports'] = 0
            row['lat'] = None
            row['lon'] = None
            out.append(row)
            continue

        ip_obj = parse_ip(ip)
        private_like = bool(ip_obj and is_private_like(ip_obj))
        cached = get_cached_enrichment(ip)
        if cached:
            enrich = cached
            needs_coords = enrich.get('lat') is None or enrich.get('lon') is None
            if (not private_like) and budget > 0 and (needs_coords or int(time.time()) - enrich.get('last_checked', 0) >= ENRICH_TTL_SECONDS):
                enrich = resolve_enrichment(ip, allow_remote=True)
                budget -= 1
        else:
            allow_remote = (not private_like) and budget > 0
            enrich = resolve_enrichment(ip, allow_remote=allow_remote)
            if allow_remote:
                budget -= 1

        row['country_code'] = row.get('country_code') or enrich.get('country_code')
        row['country_name'] = row.get('country_name') or enrich.get('country_name')
        row['asn'] = enrich.get('asn') or 'AS-UNK'
        row['as_org'] = enrich.get('as_org') or 'Unknown ASN'
        row['threat_score'] = int(enrich.get('threat_score') or 0)
        row['threat_labels'] = enrich.get('threat_labels') or []
        row['abuse_confidence'] = int(enrich.get('abuse_confidence') or 0)
        row['total_reports'] = int(enrich.get('total_reports') or 0)
        row['lat'] = enrich.get('lat')
        row['lon'] = enrich.get('lon')
        out.append(row)

    return out


def build_where(hours, category='all', query=''):
    conditions = ['ts >= ?']
    params = [window_start(hours)]

    if category != 'all':
        conditions.append('category = ?')
        params.append(category)

    if query:
        conditions.append('(COALESCE(ip, "") LIKE ? OR COALESCE(raw, "") LIKE ? OR COALESCE(path, "") LIKE ? OR COALESCE(ua_family, "") LIKE ?)')
        like = f'%{query}%'
        params.extend([like, like, like, like])

    return ' AND '.join(conditions), params


def build_summary(hours=24, limit=150, category='all', query=''):
    where, params = build_where(hours, category=category, query=query)

    totals = q(
        f"""
        SELECT
          COALESCE(SUM(CASE WHEN category='attack' THEN 1 ELSE 0 END), 0) AS attacks,
          COALESCE(SUM(CASE WHEN category='connection' THEN 1 ELSE 0 END), 0) AS connections,
          COALESCE(SUM(CASE WHEN action='ip_banned' THEN 1 ELSE 0 END), 0) AS bans,
          COALESCE(COUNT(DISTINCT CASE WHEN ip IS NOT NULL THEN ip END), 0) AS active_sources,
          COALESCE(SUM(CASE WHEN source IN ('nginx','apache') THEN 1 ELSE 0 END), 0) AS web_requests
        FROM events
        WHERE {where}
        """,
        params,
    )[0]

    top_ips = q(
        f"""
        SELECT COALESCE(ip, 'unknown') AS ip,
               COALESCE(MAX(country_code), '--') AS country_code,
               COALESCE(MAX(country_name), 'Unknown') AS country_name,
               COUNT(*) AS count
        FROM events
        WHERE {where}
        GROUP BY COALESCE(ip, 'unknown')
        ORDER BY count DESC
        LIMIT 12
        """,
        params,
    )
    top_ips = apply_enrichment(top_ips, max_remote=6)

    top_countries = q(
        f"""
        SELECT COALESCE(country_code, '--') AS country_code,
               COALESCE(country_name, 'Unknown') AS country_name,
               COUNT(*) AS count
        FROM events
        WHERE {where}
        GROUP BY COALESCE(country_code, '--'), COALESCE(country_name, 'Unknown')
        ORDER BY count DESC
        LIMIT 10
        """,
        params,
    )

    timeline = q(
        f"""
        SELECT strftime('%Y-%m-%d %H:%M', ts) AS slot,
               COALESCE(SUM(CASE WHEN category='attack' THEN 1 ELSE 0 END), 0) AS attacks,
               COALESCE(SUM(CASE WHEN category='connection' THEN 1 ELSE 0 END), 0) AS connections,
               COALESCE(SUM(CASE WHEN source IN ('nginx','apache') THEN 1 ELSE 0 END), 0) AS web
        FROM events
        WHERE {where}
        GROUP BY strftime('%Y-%m-%d %H:%M', ts)
        ORDER BY slot ASC
        """,
        params,
    )

    recent_params = params + [max(30, min(limit, 500))]
    recent = q(
        f"""
        SELECT
          ts, source, category, action,
          COALESCE(ip, '-') AS ip,
          COALESCE(port, '-') AS port,
          COALESCE(country_code, '--') AS country_code,
          COALESCE(country_name, 'Unknown') AS country_name,
          COALESCE(method, '-') AS method,
          COALESCE(path, '-') AS path,
          COALESCE(status, '-') AS status,
          COALESCE(ua_family, '-') AS ua_family,
          COALESCE(ua_device, '-') AS ua_device,
          COALESCE(user_agent, '-') AS user_agent,
          raw
        FROM events
        WHERE {where}
        ORDER BY id DESC
        LIMIT ?
        """,
        recent_params,
    )
    recent = apply_enrichment(recent, max_remote=4)

    return {
        'generated_at': to_iso_now(),
        'window_hours': hours,
        'filters': {'category': category, 'query': query},
        'totals': totals,
        'top_ips': top_ips,
        'top_countries': top_countries,
        'timeline': timeline,
        'recent': recent,
    }


def build_geo(hours=24):
    where, params = build_where(hours, category='all', query='')

    likely_ips = q(
        f"""
        SELECT ip, COUNT(*) AS count
        FROM events
        WHERE {where} AND ip IS NOT NULL
        GROUP BY ip
        ORDER BY count DESC
        LIMIT 80
        """,
        params,
    )
    apply_enrichment(likely_ips, max_remote=8)

    flow_ips_conn = q(
        f"""
        SELECT COALESCE(ip, '-') AS ip,
               COALESCE(MAX(country_code), '--') AS country_code,
               COALESCE(MAX(country_name), 'Unknown') AS country_name,
               COUNT(*) AS count
        FROM events
        WHERE {where} AND category='connection' AND ip IS NOT NULL
        GROUP BY COALESCE(ip, '-')
        ORDER BY count DESC
        LIMIT 35
        """,
        params,
    )
    flow_ips_attack = q(
        f"""
        SELECT COALESCE(ip, '-') AS ip,
               COALESCE(MAX(country_code), '--') AS country_code,
               COALESCE(MAX(country_name), 'Unknown') AS country_name,
               COUNT(*) AS count
        FROM events
        WHERE {where} AND category='attack' AND ip IS NOT NULL
        GROUP BY COALESCE(ip, '-')
        ORDER BY count DESC
        LIMIT 35
        """,
        params,
    )
    flow_ips_conn = apply_enrichment(flow_ips_conn, max_remote=10)
    flow_ips_attack = apply_enrichment(flow_ips_attack, max_remote=10)

    flows_connection = []
    for item in flow_ips_conn:
        lat = item.get('lat')
        lon = item.get('lon')
        if lat is None or lon is None:
            continue
        if item.get('country_code') in ('--', 'PR'):
            continue
        flows_connection.append({
            'ip': item.get('ip'),
            'country_code': item.get('country_code'),
            'country_name': item.get('country_name'),
            'count': int(item.get('count') or 0),
            'lat': float(lat),
            'lon': float(lon),
        })
    flows_attack = []
    for item in flow_ips_attack:
        lat = item.get('lat')
        lon = item.get('lon')
        if lat is None or lon is None:
            continue
        if item.get('country_code') in ('--', 'PR'):
            continue
        flows_attack.append({
            'ip': item.get('ip'),
            'country_code': item.get('country_code'),
            'country_name': item.get('country_name'),
            'count': int(item.get('count') or 0),
            'lat': float(lat),
            'lon': float(lon),
        })

    countries = q(
        f"""
        SELECT COALESCE(country_code, '--') AS country_code,
               COALESCE(country_name, 'Unknown') AS country_name,
               COUNT(*) AS count,
               COALESCE(SUM(CASE WHEN category='attack' THEN 1 ELSE 0 END), 0) AS attacks
        FROM events
        WHERE {where}
        GROUP BY COALESCE(country_code, '--'), COALESCE(country_name, 'Unknown')
        ORDER BY count DESC
        LIMIT 120
        """,
        params,
    )

    asn = q(
        f"""
        SELECT
          COALESCE(en.asn, 'AS-UNK') AS asn,
          COALESCE(en.as_org, 'Unknown ASN') AS as_org,
          COUNT(*) AS count,
          COALESCE(SUM(CASE WHEN e.category='attack' THEN 1 ELSE 0 END), 0) AS attacks,
          COALESCE(COUNT(DISTINCT e.ip), 0) AS unique_ips
        FROM events e
        LEFT JOIN ip_enrichment en ON e.ip = en.ip
        WHERE {where}
        GROUP BY COALESCE(en.asn, 'AS-UNK'), COALESCE(en.as_org, 'Unknown ASN')
        ORDER BY count DESC
        LIMIT 15
        """,
        params,
    )

    return {
        'generated_at': to_iso_now(),
        'window_hours': hours,
        'countries': countries,
        'top_asn': asn,
        'target': {
            'name': MAP_TARGET_NAME,
            'lat': MAP_TARGET_LAT,
            'lon': MAP_TARGET_LON,
        },
        'flows': flows_connection,
        'flows_connection': flows_connection,
        'flows_attack': flows_attack,
    }


def build_ip_drilldown(ip, hours=168):
    ip_obj = parse_ip(ip)
    if not ip_obj:
        return {'error': 'invalid_ip'}

    enrichment = resolve_enrichment(str(ip_obj), allow_remote=True)
    where, params = build_where(hours, category='all', query='')
    where = f"({where}) AND ip = ?"
    params = params + [str(ip_obj)]

    totals = q(
        f"""
        SELECT
          COUNT(*) AS total,
          COALESCE(SUM(CASE WHEN category='attack' THEN 1 ELSE 0 END), 0) AS attacks,
          COALESCE(SUM(CASE WHEN category='connection' THEN 1 ELSE 0 END), 0) AS connections,
          COALESCE(SUM(CASE WHEN action='ip_banned' THEN 1 ELSE 0 END), 0) AS bans,
          MIN(ts) AS first_seen,
          MAX(ts) AS last_seen
        FROM events
        WHERE {where}
        """,
        params,
    )[0]

    timeline = q(
        f"""
        SELECT strftime('%Y-%m-%d %H:00', ts) AS slot,
               COUNT(*) AS total,
               COALESCE(SUM(CASE WHEN category='attack' THEN 1 ELSE 0 END), 0) AS attacks,
               COALESCE(SUM(CASE WHEN category='connection' THEN 1 ELSE 0 END), 0) AS connections
        FROM events
        WHERE {where}
        GROUP BY strftime('%Y-%m-%d %H:00', ts)
        ORDER BY slot ASC
        LIMIT 240
        """,
        params,
    )

    top_actions = q(
        f"""
        SELECT action, COUNT(*) AS count
        FROM events
        WHERE {where}
        GROUP BY action
        ORDER BY count DESC
        LIMIT 12
        """,
        params,
    )

    top_paths = q(
        f"""
        SELECT path, COUNT(*) AS count
        FROM events
        WHERE {where} AND path IS NOT NULL AND path != '-'
        GROUP BY path
        ORDER BY count DESC
        LIMIT 10
        """,
        params,
    )

    ua = q(
        f"""
        SELECT ua_family, ua_device, COUNT(*) AS count
        FROM events
        WHERE {where} AND ua_family IS NOT NULL AND ua_family != '-'
        GROUP BY ua_family, ua_device
        ORDER BY count DESC
        LIMIT 10
        """,
        params,
    )

    statuses = q(
        f"""
        SELECT status, COUNT(*) AS count
        FROM events
        WHERE {where} AND status IS NOT NULL AND status != '-'
        GROUP BY status
        ORDER BY count DESC
        LIMIT 10
        """,
        params,
    )

    recent = q(
        f"""
        SELECT ts, category, source, action, path, status, ua_family, raw
        FROM events
        WHERE {where}
        ORDER BY id DESC
        LIMIT 40
        """,
        params,
    )

    return {
        'ip': str(ip_obj),
        'generated_at': to_iso_now(),
        'hours': hours,
        'enrichment': enrichment,
        'totals': totals,
        'timeline': timeline,
        'top_actions': top_actions,
        'top_paths': top_paths,
        'top_ua': ua,
        'status_breakdown': statuses,
        'recent': recent,
    }


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/summary')
def summary():
    hours = max(1, min(int(request.args.get('hours', 24)), 24 * 14))
    category = request.args.get('category', 'all')
    query = request.args.get('q', '').strip()
    limit = int(request.args.get('limit', 150))
    return jsonify(build_summary(hours=hours, limit=limit, category=category, query=query))


@app.route('/api/geo')
def geo():
    hours = max(1, min(int(request.args.get('hours', 24)), 24 * 14))
    return jsonify(build_geo(hours=hours))


@app.route('/api/ip/<path:ip>')
def ip_detail(ip):
    hours = max(1, min(int(request.args.get('hours', 168)), 24 * 30))
    payload = build_ip_drilldown(ip, hours=hours)
    status = 400 if payload.get('error') else 200
    return jsonify(payload), status


@app.route('/api/stream')
def stream():
    def event_stream():
        while True:
            payload = build_summary(hours=24, limit=120)
            yield f"data: {json.dumps(payload)}\n\n"
            time.sleep(5)

    return Response(event_stream(), mimetype='text/event-stream')


ensure_support_tables()

if __name__ == '__main__':
    host = os.getenv('SC_HOST', '0.0.0.0')
    port = int(os.getenv('SC_PORT', '1337'))
    app.run(host=host, port=port)
