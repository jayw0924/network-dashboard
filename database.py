import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "network.db")
DEVICES_JSON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "devices.json")

_write_lock = threading.Lock()


def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create tables and migrate from devices.json if DB is empty."""
    conn = _connect()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            ip TEXT PRIMARY KEY,
            mac TEXT DEFAULT '',
            hostname TEXT DEFAULT '',
            vendor TEXT DEFAULT '',
            status TEXT DEFAULT 'offline',
            last_seen TEXT DEFAULT '',
            ports TEXT DEFAULT '[]'
        );
        CREATE TABLE IF NOT EXISTS device_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            event_type TEXT NOT NULL,
            timestamp TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_events_ip ON device_events(ip);
        CREATE INDEX IF NOT EXISTS idx_events_ts ON device_events(timestamp);
        CREATE TABLE IF NOT EXISTS bandwidth_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            interface TEXT NOT NULL,
            rx_bytes_sec REAL DEFAULT 0,
            tx_bytes_sec REAL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_bw_ts ON bandwidth_samples(timestamp);
        CREATE TABLE IF NOT EXISTS latency_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip TEXT NOT NULL,
            rtt_ms REAL,
            is_external INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_lat_ts ON latency_samples(timestamp);
        CREATE INDEX IF NOT EXISTS idx_lat_ip ON latency_samples(ip);
    """)

    # Migrate from devices.json if DB is empty
    row = conn.execute("SELECT COUNT(*) FROM devices").fetchone()
    if row[0] == 0 and os.path.exists(DEVICES_JSON):
        try:
            with open(DEVICES_JSON, "r") as f:
                data = json.load(f)
            for d in data:
                conn.execute(
                    "INSERT OR IGNORE INTO devices (ip, mac, hostname, vendor, status, last_seen) "
                    "VALUES (?, ?, ?, ?, 'offline', ?)",
                    (d.get("ip", ""), d.get("mac", ""), d.get("hostname", ""),
                     d.get("vendor", ""), d.get("last_seen", ""))
                )
            conn.commit()
            print(f"Migrated {len(data)} devices from {DEVICES_JSON}")
        except (json.JSONDecodeError, IOError) as e:
            print(f"Migration error: {e}")

    conn.close()


def upsert_device(ip, mac="", hostname="", vendor="", status="online", last_seen=None):
    if last_seen is None:
        last_seen = datetime.now().isoformat()
    with _write_lock:
        conn = _connect()
        conn.execute(
            "INSERT INTO devices (ip, mac, hostname, vendor, status, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(ip) DO UPDATE SET "
            "mac=CASE WHEN excluded.mac != '' THEN excluded.mac ELSE devices.mac END, "
            "hostname=CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE devices.hostname END, "
            "vendor=CASE WHEN excluded.vendor != '' THEN excluded.vendor ELSE devices.vendor END, "
            "status=excluded.status, last_seen=excluded.last_seen",
            (ip, mac, hostname, vendor, status, last_seen)
        )
        conn.commit()
        conn.close()


def get_all_devices():
    conn = _connect()
    rows = conn.execute("SELECT * FROM devices ORDER BY ip").fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["ports"] = json.loads(d["ports"])
        except (json.JSONDecodeError, TypeError):
            d["ports"] = []
        result.append(d)
    return result


def set_all_offline():
    with _write_lock:
        conn = _connect()
        conn.execute("UPDATE devices SET status = 'offline'")
        conn.commit()
        conn.close()


def get_device_statuses():
    """Return dict of ip -> status for transition detection."""
    conn = _connect()
    rows = conn.execute("SELECT ip, status FROM devices").fetchall()
    conn.close()
    return {r["ip"]: r["status"] for r in rows}


def update_ports(ip, ports_list):
    with _write_lock:
        conn = _connect()
        conn.execute("UPDATE devices SET ports = ? WHERE ip = ?",
                      (json.dumps(ports_list), ip))
        conn.commit()
        conn.close()


def get_ports(ip):
    conn = _connect()
    row = conn.execute("SELECT ports FROM devices WHERE ip = ?", (ip,)).fetchone()
    conn.close()
    if row:
        try:
            return json.loads(row["ports"])
        except (json.JSONDecodeError, TypeError):
            pass
    return []


def add_event(ip, event_type):
    ts = datetime.now().isoformat()
    with _write_lock:
        conn = _connect()
        conn.execute("INSERT INTO device_events (ip, event_type, timestamp) VALUES (?, ?, ?)",
                      (ip, event_type, ts))
        conn.commit()
        conn.close()


def get_events(ip=None, limit=200, offset=0):
    conn = _connect()
    if ip:
        rows = conn.execute(
            "SELECT e.id, e.ip, e.event_type, e.timestamp, d.hostname "
            "FROM device_events e LEFT JOIN devices d ON e.ip = d.ip "
            "WHERE e.ip = ? ORDER BY e.timestamp DESC LIMIT ? OFFSET ?",
            (ip, limit, offset)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT e.id, e.ip, e.event_type, e.timestamp, d.hostname "
            "FROM device_events e LEFT JOIN devices d ON e.ip = d.ip "
            "ORDER BY e.timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_bandwidth_sample(interface, rx_bytes_sec, tx_bytes_sec):
    ts = datetime.now().isoformat()
    with _write_lock:
        conn = _connect()
        conn.execute(
            "INSERT INTO bandwidth_samples (timestamp, interface, rx_bytes_sec, tx_bytes_sec) "
            "VALUES (?, ?, ?, ?)",
            (ts, interface, rx_bytes_sec, tx_bytes_sec)
        )
        conn.commit()
        conn.close()


def get_bandwidth_history(minutes=60):
    cutoff = (datetime.now() - timedelta(minutes=minutes)).isoformat()
    conn = _connect()
    rows = conn.execute(
        "SELECT timestamp, rx_bytes_sec, tx_bytes_sec FROM bandwidth_samples "
        "WHERE timestamp > ? ORDER BY timestamp ASC",
        (cutoff,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def prune_bandwidth(hours=24):
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    with _write_lock:
        conn = _connect()
        conn.execute("DELETE FROM bandwidth_samples WHERE timestamp < ?", (cutoff,))
        conn.commit()
        conn.close()


def add_latency_samples(samples):
    """Batch insert latency samples: [(ts, ip, rtt_ms, is_external), ...]."""
    if not samples:
        return
    with _write_lock:
        conn = _connect()
        conn.executemany(
            "INSERT INTO latency_samples (timestamp, ip, rtt_ms, is_external) VALUES (?, ?, ?, ?)",
            samples
        )
        conn.commit()
        conn.close()


def get_latency_history(ip, minutes=60):
    """Return time series for one IP."""
    cutoff = (datetime.now() - timedelta(minutes=minutes)).isoformat()
    conn = _connect()
    rows = conn.execute(
        "SELECT timestamp, rtt_ms FROM latency_samples "
        "WHERE ip = ? AND timestamp > ? ORDER BY timestamp ASC",
        (ip, cutoff)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_latency_summary():
    """Return latest RTT + packet loss % (last 5 min) for all IPs with data."""
    cutoff = (datetime.now() - timedelta(minutes=5)).isoformat()
    conn = _connect()
    rows = conn.execute(
        "SELECT ip, is_external, "
        "COUNT(*) as total, "
        "SUM(CASE WHEN rtt_ms IS NULL THEN 1 ELSE 0 END) as lost, "
        "AVG(rtt_ms) as avg_rtt, "
        "(SELECT rtt_ms FROM latency_samples s2 "
        " WHERE s2.ip = s1.ip ORDER BY s2.timestamp DESC LIMIT 1) as latest_rtt "
        "FROM latency_samples s1 "
        "WHERE timestamp > ? "
        "GROUP BY ip",
        (cutoff,)
    ).fetchall()
    conn.close()
    result = []
    for r in rows:
        total = r["total"]
        lost = r["lost"]
        loss_pct = (lost / total * 100) if total > 0 else 0
        result.append({
            "ip": r["ip"],
            "is_external": bool(r["is_external"]),
            "latest_rtt": r["latest_rtt"],
            "avg_rtt": round(r["avg_rtt"], 2) if r["avg_rtt"] is not None else None,
            "loss_pct": round(loss_pct, 1),
            "samples": total,
        })
    return result


def prune_latency(hours=24):
    """Delete latency samples older than given hours."""
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    with _write_lock:
        conn = _connect()
        conn.execute("DELETE FROM latency_samples WHERE timestamp < ?", (cutoff,))
        conn.commit()
        conn.close()
