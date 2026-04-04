"""Auto-remediation framework for VulnScan.

Generates and executes fix commands for vulnerabilities.
"""

import logging
import json
from datetime import datetime, timezone
from typing import Optional
from .collectors.ssh import ssh_exec
from . import database as db

logger = logging.getLogger("vulnscan.remediation")


class RemediationStrategy:
    """Base class for OS-specific remediation strategies."""
    
    def can_handle(self, os_family: str, pkg_type: str) -> bool:
        raise NotImplementedError
    
    def generate_fix_command(self, package: str, target_version: str = None) -> str:
        raise NotImplementedError
    
    def assess_risk(self, package: str) -> str:
        """Assess risk level of upgrading this package."""
        critical_packages = {'kernel', 'systemd', 'glibc', 'libc', 'openssl', 'ssh', 'sudo'}
        if any(pkg in package.lower() for pkg in critical_packages):
            return 'high'
        return 'low'


class AptStrategy(RemediationStrategy):
    """Debian/Ubuntu APT remediation."""
    
    def can_handle(self, os_family: str, pkg_type: str) -> bool:
        return os_family == 'linux' and pkg_type in ('dpkg', 'deb')
    
    def generate_fix_command(self, package: str, target_version: str = None) -> str:
        if target_version:
            return f"apt-get install -y {package}={target_version}"
        return f"apt-get install -y --only-upgrade {package}"


class YumStrategy(RemediationStrategy):
    """RHEL/CentOS Yum/DNF remediation."""
    
    def can_handle(self, os_family: str, pkg_type: str) -> bool:
        return os_family == 'linux' and pkg_type in ('rpm', 'yum', 'dnf')
    
    def generate_fix_command(self, package: str, target_version: str = None) -> str:
        if target_version:
            return f"yum update -y {package}-{target_version}"
        return f"yum update -y {package}"


class ApkStrategy(RemediationStrategy):
    """Alpine APK remediation."""
    
    def can_handle(self, os_family: str, pkg_type: str) -> bool:
        return pkg_type == 'apk'
    
    def generate_fix_command(self, package: str, target_version: str = None) -> str:
        if target_version:
            return f"apk add '{package}={target_version}'"
        return f"apk upgrade {package}"


class BrewStrategy(RemediationStrategy):
    """macOS Homebrew remediation."""
    
    def can_handle(self, os_family: str, pkg_type: str) -> bool:
        return os_family == 'darwin' or pkg_type == 'brew'
    
    def generate_fix_command(self, package: str, target_version: str = None) -> str:
        return f"brew upgrade {package}"


class PipStrategy(RemediationStrategy):
    """Python pip remediation."""
    
    def can_handle(self, os_family: str, pkg_type: str) -> bool:
        return pkg_type in ('pip', 'python')
    
    def generate_fix_command(self, package: str, target_version: str = None) -> str:
        if target_version:
            return f"pip install --upgrade '{package}=={target_version}'"
        return f"pip install --upgrade {package}"


class NpmStrategy(RemediationStrategy):
    """Node.js npm remediation."""
    
    def can_handle(self, os_family: str, pkg_type: str) -> bool:
        return pkg_type in ('npm', 'node')
    
    def generate_fix_command(self, package: str, target_version: str = None) -> str:
        if target_version:
            return f"npm install {package}@{target_version}"
        return f"npm update {package}"


# Registry of all strategies
STRATEGIES = [
    AptStrategy(),
    YumStrategy(),
    ApkStrategy(),
    BrewStrategy(),
    PipStrategy(),
    NpmStrategy(),
]


def generate_fix_command(vuln: dict, host: dict) -> Optional[dict]:
    """Generate a fix command for a vulnerability.
    
    Returns dict with:
        - command: the fix command
        - strategy: which strategy generated it
        - risk: risk level (low/medium/high)
        - description: human-readable description
    """
    os_family = host.get('os_family', 'unknown')
    pkg_type = vuln.get('pkg_type', '')
    package = vuln['package_name']
    fixed_version = vuln.get('fixed_version', '')
    
    for strategy in STRATEGIES:
        if strategy.can_handle(os_family, pkg_type):
            command = strategy.generate_fix_command(package, fixed_version or None)
            risk = strategy.assess_risk(package)
            
            desc = f"Upgrade {package}"
            if fixed_version:
                desc += f" to {fixed_version}"
            
            return {
                'command': command,
                'strategy': strategy.__class__.__name__,
                'risk': risk,
                'description': desc,
                'package': package,
                'current_version': vuln['package_version'],
                'fixed_version': fixed_version
            }
    
    return None


def execute_remediation(host: dict, command: str, dry_run: bool = True) -> dict:
    """Execute a remediation command on a host.
    
    Args:
        host: Host dict from database
        command: Command to execute
        dry_run: If True, don't actually run the command
    
    Returns dict with result info
    """
    result = {
        'host_id': host['id'],
        'host_address': host['address'],
        'command': command,
        'dry_run': dry_run,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'success': False,
        'output': '',
        'error': ''
    }
    
    if dry_run:
        result['success'] = True
        result['output'] = f"DRY RUN: Would execute: {command}"
        return result
    
    # Execute the command
    rc, stdout, stderr = ssh_exec(host, command, timeout=300)
    
    result['return_code'] = rc
    result['output'] = stdout
    result['error'] = stderr
    result['success'] = (rc == 0)
    
    # Log to database
    log_remediation_action(result)
    
    return result


def remediate_vulnerability(vuln_id: int, dry_run: bool = True) -> dict:
    """Remediate a single vulnerability.
    
    Returns dict with fix command and execution result.
    """
    conn = db.get_db()
    
    # Get vulnerability and host info
    vuln_row = conn.execute(
        "SELECT v.*, h.* FROM vulnerabilities v JOIN hosts h ON v.host_id = h.id WHERE v.id = ?",
        (vuln_id,)
    ).fetchone()
    conn.close()
    
    if not vuln_row:
        return {'error': 'Vulnerability not found'}
    
    vuln = dict(vuln_row)
    host = {k: vuln[k] for k in ['id', 'address', 'ssh_user', 'ssh_password', 
                                   'ssh_key_path', 'ssh_port', 'os_family']}
    
    # Generate fix command
    fix = generate_fix_command(vuln, host)
    if not fix:
        return {'error': 'No remediation strategy available for this package type'}
    
    # Execute
    result = execute_remediation(host, fix['command'], dry_run=dry_run)
    result['fix_info'] = fix
    result['vuln_id'] = vuln_id
    
    return result


def remediate_host(host_id: int, dry_run: bool = True, severity_filter: str = None) -> list[dict]:
    """Remediate all vulnerabilities on a host.
    
    Returns list of remediation results.
    """
    # Get all open vulns for this host
    vulns = db.get_vulnerabilities(host_id=host_id, severity=severity_filter, status='open')
    
    results = []
    for vuln in vulns:
        result = remediate_vulnerability(vuln['id'], dry_run=dry_run)
        results.append(result)
    
    return results


def log_remediation_action(result: dict):
    """Log a remediation action to the database."""
    conn = db.get_db()
    conn.execute(
        """INSERT INTO remediation_log
           (host_id, vuln_id, command, dry_run, success, output, error, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            result.get('host_id'),
            result.get('vuln_id'),
            result['command'],
            result['dry_run'],
            result['success'],
            result.get('output', '')[:10000],  # Truncate
            result.get('error', '')[:10000],
            result['timestamp']
        )
    )
    conn.commit()
    conn.close()


def get_remediation_history(host_id: int = None, limit: int = 100) -> list[dict]:
    """Get remediation history from the log."""
    conn = db.get_db()
    
    if host_id:
        rows = conn.execute(
            """SELECT r.*, h.name as host_name, h.address
               FROM remediation_log r
               JOIN hosts h ON r.host_id = h.id
               WHERE r.host_id = ?
               ORDER BY r.timestamp DESC LIMIT ?
            """,
            (host_id, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT r.*, h.name as host_name, h.address
               FROM remediation_log r
               JOIN hosts h ON r.host_id = h.id
               ORDER BY r.timestamp DESC LIMIT ?
            """,
            (limit,)
        ).fetchall()
    
    conn.close()
    return [dict(r) for r in rows]
