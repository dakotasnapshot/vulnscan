"""SQLite database layer for VulnScan."""

import sqlite3
import json
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

CREATE INDEX IF NOT EXISTS idx_vulns_host ON vulnerabilities(host_id);
CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_pkgs_host ON packages(host_id);
CREATE INDEX IF NOT EXISTS idx_scans_host ON scans(host_id);
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
    conn.commit()
    conn.close()


# --- Host CRUD ---

def add_host(name: str, address: str, ssh_user: str = "root",
             ssh_password: str = None, ssh_key_path: str = None,
             ssh_port: int = 22, tags: list[str] = None) -> int:
    conn = get_db()
    cur = conn.execute(
        """INSERT INTO hosts (name, address, ssh_user, ssh_password, ssh_key_path, ssh_port, tags)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (name, address, ssh_user, ssh_password, ssh_key_path, ssh_port,
         ",".join(tags) if tags else "")
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
    conn = get_db()
    sets = ", ".join(f"{k} = ?" for k in kwargs)
    vals = list(kwargs.values()) + [host_id]
    conn.execute(f"UPDATE hosts SET {sets} WHERE id = ?", vals)
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
                   ssh_port, os_family, os_name, tags)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    host.get('name', host['address']),
                    host['address'],
                    ssh_user,
                    ssh_password,
                    ssh_key_path,
                    host.get('ssh_port', 22),
                    host.get('os_family', ''),
                    host.get('os_name', ''),
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
