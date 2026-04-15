"""SQLite database layer for VulnScan."""

import sqlite3
import json
import os
import hashlib
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DB_PATH = Path("/opt/vulnscan/db/vulnscan.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    address TEXT NOT NULL UNIQUE,
    ssh_user TEXT DEFAULT 'root',
    ssh_password TEXT,
    ssh_key_path TEXT,
    ssh_port INTEGER DEFAULT 22,
    os_family TEXT DEFAULT '',
    os_name TEXT DEFAULT '',
    platform TEXT DEFAULT '',
    vendor TEXT DEFAULT '',
    device_type TEXT DEFAULT '',
    version TEXT DEFAULT '',
    snmp_community TEXT DEFAULT '',
    snmp_version TEXT DEFAULT '2c',
    snmp_port INTEGER DEFAULT 161,
    snmp_sysdescr TEXT DEFAULT '',
    snmp_sysobjectid TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    last_scan TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    tags TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    packages_found INTEGER DEFAULT 0,
    vulns_found INTEGER DEFAULT 0,
    status TEXT DEFAULT 'running',
    error TEXT,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    pkg_type TEXT NOT NULL,
    ecosystem TEXT DEFAULT '',
    source_path TEXT DEFAULT '',
    host_id INTEGER NOT NULL,
    scan_id INTEGER NOT NULL,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    package_name TEXT NOT NULL,
    package_version TEXT NOT NULL,
    pkg_type TEXT DEFAULT '',
    host_id INTEGER NOT NULL,
    scan_id INTEGER NOT NULL,
    severity TEXT DEFAULT 'unknown',
    cvss_score REAL,
    summary TEXT DEFAULT '',
    fixed_version TEXT DEFAULT '',
    references_json TEXT DEFAULT '[]',
    source_path TEXT DEFAULT '',
    first_seen TEXT DEFAULT (datetime('now')),
    last_seen TEXT DEFAULT (datetime('now')),
    status TEXT DEFAULT 'open',
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS credential_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    ssh_user TEXT NOT NULL,
    ssh_password TEXT,
    ssh_key_path TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS advisory_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    vendor TEXT DEFAULT '',
    source_type TEXT DEFAULT 'local_json',
    path TEXT DEFAULT '',
    url TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS device_facts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    scan_id INTEGER,
    fact_key TEXT NOT NULL,
    fact_value TEXT DEFAULT '',
    source TEXT DEFAULT '',
    collected_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scan_schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    host_id INTEGER,
    cron_expr TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now')),
    last_run TEXT,
    next_run TEXT,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS compliance_policy_settings (
    policy_id TEXT PRIMARY KEY,
    enabled INTEGER DEFAULT 1,
    threshold INTEGER,
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    enabled INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_vulns_host ON vulnerabilities(host_id);
CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_pkgs_host ON packages(host_id);
CREATE INDEX IF NOT EXISTS idx_scans_host ON scans(host_id);
CREATE INDEX IF NOT EXISTS idx_device_facts_host ON device_facts(host_id);
CREATE INDEX IF NOT EXISTS idx_scan_schedules_enabled ON scan_schedules(enabled);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
"""


def get_db() -> sqlite3.Connection:
    """Get a database connection with row factory."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Initialize the database schema."""
    conn = get_db()
    conn.executescript(SCHEMA)
    migrations = [
        "ALTER TABLE hosts ADD COLUMN platform TEXT DEFAULT ''",
        "ALTER TABLE hosts ADD COLUMN vendor TEXT DEFAULT ''",
        "ALTER TABLE hosts ADD COLUMN device_type TEXT DEFAULT ''",
        "ALTER TABLE hosts ADD COLUMN version TEXT DEFAULT ''",
        "ALTER TABLE hosts ADD COLUMN snmp_community TEXT DEFAULT ''",
        "ALTER TABLE hosts ADD COLUMN snmp_version TEXT DEFAULT '2c'",
        "ALTER TABLE hosts ADD COLUMN snmp_port INTEGER DEFAULT 161",
        "ALTER TABLE hosts ADD COLUMN snmp_sysdescr TEXT DEFAULT ''",
        "ALTER TABLE hosts ADD COLUMN snmp_sysobjectid TEXT DEFAULT ''",
        "ALTER TABLE scan_schedules ADD COLUMN last_run TEXT",
        "ALTER TABLE scan_schedules ADD COLUMN next_run TEXT",
    ]
    for sql in migrations:
        try:
            conn.execute(sql)
        except sqlite3.OperationalError:
            pass
    conn.commit()
    ensure_default_admin(conn)
    conn.close()


def _hash_password(password: str, salt: str = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 200_000).hex()
    return f"pbkdf2_sha256${salt}${digest}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        scheme, salt, digest = password_hash.split('$', 2)
        if scheme != 'pbkdf2_sha256':
            return False
        candidate = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 200_000).hex()
        return secrets.compare_digest(candidate, digest)
    except Exception:
        return False


def ensure_default_admin(conn=None):
    owns_conn = conn is None
    conn = conn or get_db()
    row = conn.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
    if not row:
        default_password = os.environ.get('VULNSCAN_PASSWORD', 'changeme')
        conn.execute(
            "INSERT INTO users (username, password_hash, role, enabled) VALUES (?, ?, 'admin', 1)",
            ('admin', _hash_password(default_password)),
        )
        conn.commit()
    if owns_conn:
        conn.close()


# --- Host CRUD ---

def add_host(name: str, address: str, ssh_user: str = "root",
             ssh_password: str = None, ssh_key_path: str = None,
             ssh_port: int = 22, tags: list[str] = None,
             platform: str = "", vendor: str = "", device_type: str = "",
             version: str = "", snmp_community: str = None,
             snmp_version: str = "2c", snmp_port: int = 161,
             snmp_sysdescr: str = "", snmp_sysobjectid: str = "") -> int:
    conn = get_db()
    cur = conn.execute(
        """INSERT INTO hosts (name, address, ssh_user, ssh_password, ssh_key_path, ssh_port,
           os_family, os_name, platform, vendor, device_type, version,
           snmp_community, snmp_version, snmp_port, snmp_sysdescr, snmp_sysobjectid, tags)
           VALUES (?, ?, ?, ?, ?, ?, '', '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (name, address, ssh_user, ssh_password, ssh_key_path, ssh_port,
         platform, vendor, device_type, version, snmp_community, snmp_version,
         snmp_port, snmp_sysdescr, snmp_sysobjectid, ",".join(tags) if tags else "")
    )
    conn.commit()
    host_id = cur.lastrowid
    conn.close()
    return host_id


def get_host(host_id: int) -> Optional[dict]:
    conn = get_db()
    row = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_host_by_address(address: str) -> Optional[dict]:
    conn = get_db()
    row = conn.execute("SELECT * FROM hosts WHERE address = ?", (address,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_device_facts(host_id: int, limit: int = 100) -> list[dict]:
    conn = get_db()
    rows = conn.execute(
        """SELECT fact_key, fact_value, source, collected_at, scan_id
           FROM device_facts
           WHERE host_id = ?
           ORDER BY collected_at DESC, id DESC
           LIMIT ?""",
        (host_id, limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def list_hosts(enabled_only: bool = False) -> list[dict]:
    conn = get_db()
    q = "SELECT * FROM hosts"
    if enabled_only:
        q += " WHERE enabled = 1"
    q += " ORDER BY name"
    rows = conn.execute(q).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_host(host_id: int, **kwargs):
    if not kwargs:
        return
    conn = get_db()
    sets = ", ".join(f"{k} = ?" for k in kwargs)
    vals = list(kwargs.values()) + [host_id]
    conn.execute(f"UPDATE hosts SET {sets} WHERE id = ?", vals)
    conn.commit()
    conn.close()


def upsert_discovered_host(host: dict, credential_profile_id: int = None) -> tuple[int, str]:
    """Create or update a discovered host, preserving existing credentials when possible."""
    existing = get_host_by_address(host["address"])

    creds = {}
    if credential_profile_id:
        profile = get_credential_profile(credential_profile_id)
        if profile:
            creds = {
                "ssh_user": profile["ssh_user"],
                "ssh_password": profile.get("ssh_password"),
                "ssh_key_path": profile.get("ssh_key_path"),
            }

    name = host.get("name") or host.get("hostname") or host.get("snmp_sysname") or host["address"]
    payload = {
        "name": name,
        "address": host["address"],
        "ssh_user": host.get("ssh_user") or creds.get("ssh_user", "root"),
        "ssh_password": host.get("ssh_password") if host.get("ssh_accessible") else creds.get("ssh_password"),
        "ssh_key_path": host.get("ssh_key_path") if host.get("ssh_accessible") else creds.get("ssh_key_path"),
        "ssh_port": host.get("ssh_port", 22),
        "platform": host.get("platform", ""),
        "vendor": host.get("vendor", ""),
        "device_type": host.get("device_type", ""),
        "version": host.get("version", ""),
        "snmp_community": host.get("snmp_community") or "",
        "snmp_version": host.get("snmp_version", "2c"),
        "snmp_port": host.get("snmp_port", 161),
        "snmp_sysdescr": host.get("snmp_sysdescr", ""),
        "snmp_sysobjectid": host.get("snmp_sysobjectid", ""),
    }

    optional_updates = {
        "os_family": host.get("os_family", ""),
        "os_name": host.get("os_name", ""),
    }

    if existing:
        updates = {}
        for key, value in payload.items():
            if key == "address":
                continue
            if value not in (None, ""):
                updates[key] = value
        for key, value in optional_updates.items():
            if value and value != "unknown":
                updates[key] = value
        update_host(existing["id"], **updates)
        return existing["id"], "updated"

    host_id = add_host(
        name=payload["name"],
        address=payload["address"],
        ssh_user=payload["ssh_user"],
        ssh_password=payload["ssh_password"],
        ssh_key_path=payload["ssh_key_path"],
        ssh_port=payload["ssh_port"],
        tags=host.get("tags", []),
        platform=payload["platform"],
        vendor=payload["vendor"],
        device_type=payload["device_type"],
        version=payload["version"],
        snmp_community=payload["snmp_community"],
        snmp_version=payload["snmp_version"],
        snmp_port=payload["snmp_port"],
        snmp_sysdescr=payload["snmp_sysdescr"],
        snmp_sysobjectid=payload["snmp_sysobjectid"],
    )
    update_host(host_id, **{k: v for k, v in optional_updates.items() if v and v != "unknown"})
    return host_id, "created"


def insert_device_facts(host_id: int, scan_id: int = None, facts: dict = None, source: str = ""):
    if not facts:
        return
    conn = get_db()
    rows = [
        (host_id, scan_id, str(k), "" if v is None else str(v), source)
        for k, v in facts.items()
    ]
    conn.executemany(
        """INSERT INTO device_facts (host_id, scan_id, fact_key, fact_value, source)
           VALUES (?, ?, ?, ?, ?)""",
        rows,
    )
    conn.commit()
    conn.close()


def delete_host(host_id: int):
    conn = get_db()
    conn.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
    conn.commit()
    conn.close()


def bulk_add_hosts(hosts: list[dict], credential_profile_id: int = None) -> list[int]:
    """Add multiple hosts at once, optionally using a credential profile.
    
    Args:
        hosts: List of host dicts with name, address, etc.
        credential_profile_id: If provided, use this profile's credentials as defaults
    
    Returns:
        List of created host IDs
    """
    # Get credential profile if specified
    creds = {}
    if credential_profile_id:
        profile = get_credential_profile(credential_profile_id)
        if profile:
            creds = {
                'ssh_user': profile['ssh_user'],
                'ssh_password': profile.get('ssh_password'),
                'ssh_key_path': profile.get('ssh_key_path')
            }
    
    conn = get_db()
    host_ids = []
    
    for host in hosts:
        # Use provided credentials or fall back to profile defaults
        ssh_user = host.get('ssh_user') or creds.get('ssh_user', 'root')
        ssh_password = host.get('ssh_password') or creds.get('ssh_password')
        ssh_key_path = host.get('ssh_key_path') or creds.get('ssh_key_path')
        
        try:
            cur = conn.execute(
                """INSERT INTO hosts (name, address, ssh_user, ssh_password, ssh_key_path,
                   ssh_port, os_family, os_name, platform, vendor, device_type, version,
                   snmp_community, snmp_version, snmp_port, snmp_sysdescr, snmp_sysobjectid, tags)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    host.get('name', host['address']),
                    host['address'],
                    ssh_user,
                    ssh_password,
                    ssh_key_path,
                    host.get('ssh_port', 22),
                    host.get('os_family', ''),
                    host.get('os_name', ''),
                    host.get('platform', ''),
                    host.get('vendor', ''),
                    host.get('device_type', ''),
                    host.get('version', ''),
                    host.get('snmp_community', ''),
                    host.get('snmp_version', '2c'),
                    host.get('snmp_port', 161),
                    host.get('snmp_sysdescr', ''),
                    host.get('snmp_sysobjectid', ''),
                    ",".join(host.get('tags', []))
                )
            )
            host_ids.append(cur.lastrowid)
        except sqlite3.IntegrityError:
            # Host with this address already exists, skip
            pass
    
    conn.commit()
    conn.close()
    return host_ids


# --- Scan CRUD ---

def create_scan(host_id: int) -> int:
    conn = get_db()
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO scans (host_id, started_at) VALUES (?, ?)",
        (host_id, now)
    )
    conn.commit()
    scan_id = cur.lastrowid
    conn.close()
    return scan_id


def finish_scan(scan_id: int, packages_found: int, vulns_found: int,
                status: str = "completed", error: str = None):
    conn = get_db()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """UPDATE scans SET finished_at = ?, packages_found = ?, vulns_found = ?,
           status = ?, error = ? WHERE id = ?""",
        (now, packages_found, vulns_found, status, error, scan_id)
    )
    # Update host last_scan
    conn.execute(
        "UPDATE hosts SET last_scan = ? WHERE id = (SELECT host_id FROM scans WHERE id = ?)",
        (now, scan_id)
    )
    conn.commit()
    conn.close()


def get_scan(scan_id: int) -> Optional[dict]:
    conn = get_db()
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_scans(host_id: int = None, limit: int = 50) -> list[dict]:
    conn = get_db()
    if host_id:
        rows = conn.execute(
            "SELECT s.*, h.name as host_name FROM scans s JOIN hosts h ON s.host_id = h.id WHERE s.host_id = ? ORDER BY s.started_at DESC LIMIT ?",
            (host_id, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT s.*, h.name as host_name FROM scans s JOIN hosts h ON s.host_id = h.id ORDER BY s.started_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# --- Scheduler CRUD ---

def add_scan_schedule(name: str, cron_expr: str, host_id: int = None, enabled: bool = True,
                      next_run: str = None) -> int:
    conn = get_db()
    cur = conn.execute(
        """INSERT INTO scan_schedules (name, host_id, cron_expr, enabled, next_run)
           VALUES (?, ?, ?, ?, ?)""",
        (name, host_id, cron_expr, 1 if enabled else 0, next_run)
    )
    conn.commit()
    schedule_id = cur.lastrowid
    conn.close()
    return schedule_id


def list_scan_schedules() -> list[dict]:
    conn = get_db()
    rows = conn.execute(
        """SELECT s.*, h.name as host_name
           FROM scan_schedules s
           LEFT JOIN hosts h ON s.host_id = h.id
           ORDER BY s.enabled DESC, s.name ASC"""
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_scan_schedule(schedule_id: int) -> Optional[dict]:
    conn = get_db()
    row = conn.execute(
        """SELECT s.*, h.name as host_name
           FROM scan_schedules s
           LEFT JOIN hosts h ON s.host_id = h.id
           WHERE s.id = ?""",
        (schedule_id,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def update_scan_schedule(schedule_id: int, **kwargs):
    if not kwargs:
        return
    conn = get_db()
    sets = ", ".join(f"{k} = ?" for k in kwargs)
    vals = list(kwargs.values()) + [schedule_id]
    conn.execute(f"UPDATE scan_schedules SET {sets} WHERE id = ?", vals)
    conn.commit()
    conn.close()


def delete_scan_schedule(schedule_id: int):
    conn = get_db()
    conn.execute("DELETE FROM scan_schedules WHERE id = ?", (schedule_id,))
    conn.commit()
    conn.close()


# --- Compliance Policy Settings ---

def list_policy_settings() -> list[dict]:
    conn = get_db()
    rows = conn.execute(
        "SELECT policy_id, enabled, threshold, updated_at FROM compliance_policy_settings ORDER BY policy_id"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_policy_setting(policy_id: str) -> Optional[dict]:
    conn = get_db()
    row = conn.execute(
        "SELECT policy_id, enabled, threshold, updated_at FROM compliance_policy_settings WHERE policy_id = ?",
        (policy_id,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def upsert_policy_setting(policy_id: str, enabled: bool = True, threshold: int = None):
    conn = get_db()
    conn.execute(
        """INSERT INTO compliance_policy_settings (policy_id, enabled, threshold, updated_at)
           VALUES (?, ?, ?, datetime('now'))
           ON CONFLICT(policy_id) DO UPDATE SET
             enabled = excluded.enabled,
             threshold = excluded.threshold,
             updated_at = datetime('now')""",
        (policy_id, 1 if enabled else 0, threshold),
    )
    conn.commit()
    conn.close()


# --- Users / Auth ---

def list_users() -> list[dict]:
    conn = get_db()
    rows = conn.execute(
        "SELECT id, username, role, enabled, created_at, updated_at FROM users ORDER BY username"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_user_by_username(username: str) -> Optional[dict]:
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def create_user(username: str, password: str, role: str = 'viewer', enabled: bool = True) -> int:
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO users (username, password_hash, role, enabled) VALUES (?, ?, ?, ?)",
        (username, _hash_password(password), role, 1 if enabled else 0),
    )
    conn.commit()
    user_id = cur.lastrowid
    conn.close()
    return user_id


def update_user(user_id: int, **kwargs):
    if not kwargs:
        return
    updates = dict(kwargs)
    if 'password' in updates:
        updates['password_hash'] = _hash_password(updates.pop('password'))
    updates['updated_at'] = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    sets = ", ".join(f"{k} = ?" for k in updates)
    vals = list(updates.values()) + [user_id]
    conn.execute(f"UPDATE users SET {sets} WHERE id = ?", vals)
    conn.commit()
    conn.close()


def authenticate_user(username: str, password: str) -> Optional[dict]:
    user = get_user_by_username(username)
    if not user or not user.get('enabled'):
        return None
    if not verify_password(password, user['password_hash']):
        return None
    return {
        'id': user['id'],
        'username': user['username'],
        'role': user['role'],
        'enabled': user['enabled'],
    }


# --- Package CRUD ---

def insert_packages(packages: list[dict]):
    if not packages:
        return
    conn = get_db()
    conn.executemany(
        """INSERT INTO packages (name, version, pkg_type, ecosystem, source_path, host_id, scan_id)
           VALUES (:name, :version, :pkg_type, :ecosystem, :source_path, :host_id, :scan_id)""",
        packages
    )
    conn.commit()
    conn.close()


def get_packages(host_id: int, scan_id: int = None) -> list[dict]:
    conn = get_db()
    if scan_id:
        rows = conn.execute(
            "SELECT * FROM packages WHERE host_id = ? AND scan_id = ? ORDER BY pkg_type, name",
            (host_id, scan_id)
        ).fetchall()
    else:
        # Latest scan
        rows = conn.execute(
            """SELECT p.* FROM packages p
               JOIN (SELECT MAX(id) as max_scan FROM scans WHERE host_id = ? AND status = 'completed') s
               ON p.scan_id = s.max_scan
               ORDER BY p.pkg_type, p.name""",
            (host_id,)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# --- Vulnerability CRUD ---

def insert_vulnerabilities(vulns: list[dict]):
    if not vulns:
        return
    conn = get_db()
    for v in vulns:
        # Check if this vuln already exists for this host (by CVE + package)
        existing = conn.execute(
            """SELECT id FROM vulnerabilities
               WHERE cve_id = ? AND package_name = ? AND host_id = ? AND status != 'fixed'""",
            (v["cve_id"], v["package_name"], v["host_id"])
        ).fetchone()
        if existing:
            # Update last_seen and scan_id
            conn.execute(
                """UPDATE vulnerabilities SET last_seen = datetime('now'),
                   scan_id = ?, package_version = ?, severity = ?,
                   cvss_score = ?, fixed_version = ?
                   WHERE id = ?""",
                (v["scan_id"], v["package_version"], v["severity"],
                 v.get("cvss_score"), v.get("fixed_version", ""), existing["id"])
            )
        else:
            conn.execute(
                """INSERT INTO vulnerabilities
                   (cve_id, package_name, package_version, pkg_type, host_id, scan_id,
                    severity, cvss_score, summary, fixed_version, references_json, source_path)
                   VALUES (:cve_id, :package_name, :package_version, :pkg_type, :host_id,
                    :scan_id, :severity, :cvss_score, :summary, :fixed_version,
                    :references_json, :source_path)""",
                v
            )
    conn.commit()
    conn.close()


def get_vulnerabilities(host_id: int = None, severity: str = None,
                        status: str = None, limit: int = 500) -> list[dict]:
    conn = get_db()
    q = """SELECT v.*, h.name as host_name FROM vulnerabilities v
           JOIN hosts h ON v.host_id = h.id WHERE 1=1"""
    params = []
    if host_id:
        q += " AND v.host_id = ?"
        params.append(host_id)
    if severity:
        q += " AND v.severity = ?"
        params.append(severity)
    if status:
        q += " AND v.status = ?"
        params.append(status)
    else:
        q += " AND v.status = 'open'"
    q += " ORDER BY CASE v.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, v.last_seen DESC"
    q += f" LIMIT {limit}"
    rows = conn.execute(q, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_vuln_status(vuln_id: int, status: str):
    conn = get_db()
    conn.execute("UPDATE vulnerabilities SET status = ? WHERE id = ?", (status, vuln_id))
    conn.commit()
    conn.close()


def get_dashboard_stats() -> dict:
    conn = get_db()
    stats = {}
    stats["total_hosts"] = conn.execute("SELECT COUNT(*) FROM hosts WHERE enabled = 1").fetchone()[0]
    stats["total_vulns"] = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE status = 'open'").fetchone()[0]
    stats["critical"] = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE status = 'open' AND severity = 'critical'").fetchone()[0]
    stats["high"] = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE status = 'open' AND severity = 'high'").fetchone()[0]
    stats["medium"] = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE status = 'open' AND severity = 'medium'").fetchone()[0]
    stats["low"] = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE status = 'open' AND severity = 'low'").fetchone()[0]

    # Recent scans
    rows = conn.execute(
        """SELECT s.*, h.name as host_name FROM scans s
           JOIN hosts h ON s.host_id = h.id
           ORDER BY s.started_at DESC LIMIT 10"""
    ).fetchall()
    stats["recent_scans"] = [dict(r) for r in rows]

    # Vulns by host
    rows = conn.execute(
        """SELECT h.name, h.id as host_id, h.address,
           COUNT(CASE WHEN v.severity = 'critical' THEN 1 END) as critical,
           COUNT(CASE WHEN v.severity = 'high' THEN 1 END) as high,
           COUNT(CASE WHEN v.severity = 'medium' THEN 1 END) as medium,
           COUNT(CASE WHEN v.severity = 'low' THEN 1 END) as low,
           COUNT(v.id) as total
           FROM hosts h
           LEFT JOIN vulnerabilities v ON h.id = v.host_id AND v.status = 'open'
           WHERE h.enabled = 1
           GROUP BY h.id ORDER BY total DESC"""
    ).fetchall()
    stats["hosts_summary"] = [dict(r) for r in rows]

    conn.close()
    return stats


# Initialize on import
init_db()


# --- Vulnerability Fix Info ---

def get_vulnerability_with_fix(vuln_id: int) -> Optional[dict]:
    """Get vulnerability with generated fix command."""
    from . import remediation
    
    conn = get_db()
    row = conn.execute(
        """SELECT v.*, h.os_family, h.name as host_name, h.address
           FROM vulnerabilities v
           JOIN hosts h ON v.host_id = h.id
           WHERE v.id = ?
        """,
        (vuln_id,)
    ).fetchone()
    conn.close()
    
    if not row:
        return None
    
    vuln = dict(row)
    
    # Generate fix command
    host = {
        'os_family': vuln['os_family'],
        'address': vuln['address']
    }
    fix = remediation.generate_fix_command(vuln, host)
    
    if fix:
        vuln['fix_command'] = fix['command']
        vuln['fix_strategy'] = fix['strategy']
        vuln['fix_risk'] = fix['risk']
        vuln['fix_description'] = fix['description']
    
    # Parse references
    try:
        vuln['references'] = json.loads(vuln.get('references_json', '[]'))
    except:
        vuln['references'] = []
    
    return vuln


# --- Credential Profiles ---

def add_credential_profile(name: str, ssh_user: str, ssh_password: str = None, 
                          ssh_key_path: str = None) -> int:
    """Add a new credential profile."""
    conn = get_db()
    cur = conn.execute(
        """INSERT INTO credential_profiles (name, ssh_user, ssh_password, ssh_key_path)
           VALUES (?, ?, ?, ?)""",
        (name, ssh_user, ssh_password, ssh_key_path)
    )
    conn.commit()
    profile_id = cur.lastrowid
    conn.close()
    return profile_id


def get_credential_profile(profile_id: int) -> Optional[dict]:
    """Get a credential profile by ID."""
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM credential_profiles WHERE id = ?", 
        (profile_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def list_credential_profiles() -> list[dict]:
    """List all credential profiles."""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM credential_profiles ORDER BY name"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_credential_profile(profile_id: int, **kwargs):
    """Update a credential profile."""
    conn = get_db()
    sets = ", ".join(f"{k} = ?" for k in kwargs)
    vals = list(kwargs.values()) + [profile_id]
    conn.execute(f"UPDATE credential_profiles SET {sets} WHERE id = ?", vals)
    conn.commit()
    conn.close()


def delete_credential_profile(profile_id: int):
    """Delete a credential profile."""
    conn = get_db()
    conn.execute("DELETE FROM credential_profiles WHERE id = ?", (profile_id,))
    conn.commit()
    conn.close()
