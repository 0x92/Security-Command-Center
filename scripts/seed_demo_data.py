#!/usr/bin/env python3
import json
import os
import random
import sqlite3
from datetime import datetime, timedelta, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.getenv('SC_DATA_DIR', os.path.join(BASE_DIR, 'data'))
DB_PATH = os.getenv('SC_DB_PATH', os.path.join(DATA_DIR, 'security_events.db'))

random.seed(42)
os.makedirs(DATA_DIR, exist_ok=True)

IPS = [
    ("198.51.100.12", "US", "United States", "AS64510", "Example Transit US", 37.7749, -122.4194),
    ("198.51.100.77", "DE", "Germany", "AS64511", "Example Carrier DE", 52.52, 13.405),
    ("203.0.113.9", "FR", "France", "AS64512", "Example Fiber FR", 48.8566, 2.3522),
    ("203.0.113.120", "GB", "United Kingdom", "AS64513", "Example Backbone UK", 51.5074, -0.1278),
    ("192.0.2.44", "SG", "Singapore", "AS64514", "Example Datacenter SG", 1.3521, 103.8198),
    ("192.0.2.88", "BR", "Brazil", "AS64515", "Example Network BR", -23.5505, -46.6333),
]

ACTIONS = [
    ("attack", "ssh_failed_login"),
    ("attack", "ufw_block"),
    ("attack", "http_4xx"),
    ("attack", "http_5xx"),
    ("connection", "http_request"),
    ("connection", "ssh_accepted"),
    ("info", "ip_unbanned"),
]

UAS = [
    "Mozilla/5.0 (compatible; DemoScanner/1.0)",
    "curl/8.5.0",
    "python-requests/2.32.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
]

PATHS = ["/", "/admin", "/api/login", "/api/status", "/wp-login.php", "/health"]

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row

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
        updated_at TEXT NOT NULL,
        lat REAL,
        lon REAL
    )
    """
)

conn.execute("DELETE FROM events")
conn.execute("DELETE FROM ip_enrichment")

now = datetime.now(timezone.utc)
for i in range(280):
    ip, cc, country, asn, as_org, lat, lon = random.choice(IPS)
    category, action = random.choice(ACTIONS)
    t = now - timedelta(minutes=random.randint(0, 24 * 60))
    status = random.choice([200, 200, 200, 401, 403, 404, 500, 502]) if "http" in action else None
    method = random.choice(["GET", "POST", "HEAD"]) if "http" in action else None
    path = random.choice(PATHS) if "http" in action else None
    port = random.choice([22, 80, 443])
    ua = random.choice(UAS)
    raw = f"demo event {action} from {ip}"

    conn.execute(
        """
        INSERT INTO events(
            ts, source, category, action, ip, port, raw,
            country_code, country_name, method, path, status,
            user_agent, ua_family, ua_device
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            t.isoformat(),
            "demo",
            category,
            action,
            ip,
            port,
            raw,
            cc,
            country,
            method,
            path,
            status,
            ua,
            "DemoBrowser",
            "desktop",
        ),
    )

for idx, (ip, cc, country, asn, as_org, lat, lon) in enumerate(IPS, start=1):
    threat = 25 + idx * 9
    labels = ["demo_seed"]
    if threat >= 55:
        labels.append("elevated_activity")
    conn.execute(
        """
        INSERT INTO ip_enrichment(
            ip, country_code, country_name, asn, as_org,
            threat_score, threat_labels, abuse_confidence,
            total_reports, last_checked, updated_at, lat, lon
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            ip,
            cc,
            country,
            asn,
            as_org,
            threat,
            json.dumps(labels),
            min(95, threat),
            idx * 3,
            int(now.timestamp()),
            now.isoformat(),
            lat,
            lon,
        ),
    )

conn.commit()
conn.close()
print(f"Seeded demo DB: {DB_PATH}")
