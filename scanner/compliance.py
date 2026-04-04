"""Compliance and policy enforcement for VulnScan.

Define policies, evaluate them, and generate compliance reports.
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from . import database as db

logger = logging.getLogger("vulnscan.compliance")


class Policy:
    """Base class for compliance policies."""
    
    def __init__(self, policy_id: str, name: str, description: str, severity: str = 'medium'):
        self.policy_id = policy_id
        self.name = name
        self.description = description
        self.severity = severity
    
    def evaluate(self) -> dict:
        """Evaluate the policy.
        
        Returns dict with:
            - compliant: bool
            - message: str
            - violations: list of violation details
        """
        raise NotImplementedError


class NoCriticalVulnsPolicy(Policy):
    """Policy: No critical vulnerabilities older than X days."""
    
    def __init__(self, max_age_days: int = 7):
        super().__init__(
            'no-critical-vulns',
            f'No Critical Vulnerabilities > {max_age_days} Days',
            f'Critical vulnerabilities must be remediated within {max_age_days} days',
            severity='critical'
        )
        self.max_age_days = max_age_days
    
    def evaluate(self) -> dict:
        conn = db.get_db()
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.max_age_days)).isoformat()
        
        rows = conn.execute(
            """SELECT v.*, h.name as host_name
               FROM vulnerabilities v
               JOIN hosts h ON v.host_id = h.id
               WHERE v.severity = 'critical' AND v.status = 'open'
               AND v.first_seen < ?
            """,
            (cutoff,)
        ).fetchall()
        conn.close()
        
        violations = [dict(r) for r in rows]
        compliant = len(violations) == 0
        
        return {
            'compliant': compliant,
            'message': f'{len(violations)} critical vulnerability(ies) older than {self.max_age_days} days' if not compliant else 'Compliant',
            'violations': violations
        }


class NoHighVulnsPolicy(Policy):
    """Policy: No high vulnerabilities older than X days."""
    
    def __init__(self, max_age_days: int = 14):
        super().__init__(
            'no-high-vulns',
            f'No High Vulnerabilities > {max_age_days} Days',
            f'High vulnerabilities must be remediated within {max_age_days} days',
            severity='high'
        )
        self.max_age_days = max_age_days
    
    def evaluate(self) -> dict:
        conn = db.get_db()
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.max_age_days)).isoformat()
        
        rows = conn.execute(
            """SELECT v.*, h.name as host_name
               FROM vulnerabilities v
               JOIN hosts h ON v.host_id = h.id
               WHERE v.severity = 'high' AND v.status = 'open'
               AND v.first_seen < ?
            """,
            (cutoff,)
        ).fetchall()
        conn.close()
        
        violations = [dict(r) for r in rows]
        compliant = len(violations) == 0
        
        return {
            'compliant': compliant,
            'message': f'{len(violations)} high vulnerability(ies) older than {self.max_age_days} days' if not compliant else 'Compliant',
            'violations': violations
        }


class RecentScansPolicy(Policy):
    """Policy: All hosts must be scanned within X days."""
    
    def __init__(self, max_age_days: int = 7):
        super().__init__(
            'recent-scans',
            f'All Hosts Scanned Within {max_age_days} Days',
            f'Every enabled host must have a successful scan within {max_age_days} days',
            severity='medium'
        )
        self.max_age_days = max_age_days
    
    def evaluate(self) -> dict:
        conn = db.get_db()
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.max_age_days)).isoformat()
        
        # Get enabled hosts that haven't been scanned recently
        rows = conn.execute(
            """SELECT h.*
               FROM hosts h
               WHERE h.enabled = 1
               AND (h.last_scan IS NULL OR h.last_scan < ?)
            """,
            (cutoff,)
        ).fetchall()
        conn.close()
        
        violations = [dict(r) for r in rows]
        compliant = len(violations) == 0
        
        return {
            'compliant': compliant,
            'message': f'{len(violations)} host(s) not scanned within {self.max_age_days} days' if not compliant else 'Compliant',
            'violations': violations
        }


class MaxVulnerabilityCountPolicy(Policy):
    """Policy: Total vulnerability count must not exceed threshold."""
    
    def __init__(self, max_count: int = 100):
        super().__init__(
            'max-vuln-count',
            f'Total Vulnerabilities ≤ {max_count}',
            f'The total number of open vulnerabilities must not exceed {max_count}',
            severity='medium'
        )
        self.max_count = max_count
    
    def evaluate(self) -> dict:
        conn = db.get_db()
        row = conn.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE status = 'open'"
        ).fetchone()
        conn.close()
        
        count = row[0]
        compliant = count <= self.max_count
        
        return {
            'compliant': compliant,
            'message': f'Total: {count} vulnerabilities (limit: {self.max_count})' if not compliant else f'{count} open vulnerabilities (within limit)',
            'violations': [] if compliant else [{'total_count': count, 'max_allowed': self.max_count}]
        }


# Default policy set
DEFAULT_POLICIES = [
    NoCriticalVulnsPolicy(max_age_days=7),
    NoHighVulnsPolicy(max_age_days=14),
    RecentScansPolicy(max_age_days=7),
    MaxVulnerabilityCountPolicy(max_count=100),
]


def load_policies_from_db() -> list[Policy]:
    """Load custom policies from database."""
    # For now, return defaults
    # TODO: Store custom policies in DB
    return DEFAULT_POLICIES


def evaluate_policies(policies: list[Policy] = None) -> dict:
    """Evaluate all policies and return compliance status.
    
    Returns dict with overall status and policy results.
    """
    if policies is None:
        policies = load_policies_from_db()
    
    results = []
    overall_compliant = True
    
    for policy in policies:
        try:
            result = policy.evaluate()
            result['policy_id'] = policy.policy_id
            result['policy_name'] = policy.name
            result['policy_description'] = policy.description
            result['policy_severity'] = policy.severity
            results.append(result)
            
            if not result['compliant']:
                overall_compliant = False
        except Exception as e:
            logger.error(f"Error evaluating policy {policy.policy_id}: {e}")
            results.append({
                'policy_id': policy.policy_id,
                'policy_name': policy.name,
                'compliant': False,
                'message': f'Error: {str(e)}',
                'violations': []
            })
            overall_compliant = False
    
    return {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'overall_compliant': overall_compliant,
        'policies_evaluated': len(results),
        'policies_passed': sum(1 for r in results if r['compliant']),
        'policies_failed': sum(1 for r in results if not r['compliant']),
        'results': results
    }


def generate_compliance_report(format: str = 'json') -> str:
    """Generate a compliance report.
    
    Args:
        format: 'json' or 'csv'
    
    Returns formatted report string
    """
    evaluation = evaluate_policies()
    
    if format == 'json':
        return json.dumps(evaluation, indent=2, default=str)
    
    elif format == 'csv':
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow(['Policy ID', 'Policy Name', 'Compliant', 'Severity', 'Message', 'Violation Count'])
        
        # Rows
        for result in evaluation['results']:
            writer.writerow([
                result['policy_id'],
                result['policy_name'],
                'Yes' if result['compliant'] else 'No',
                result.get('policy_severity', 'medium'),
                result['message'],
                len(result.get('violations', []))
            ])
        
        return output.getvalue()
    
    else:
        raise ValueError(f"Unsupported format: {format}")


def get_compliance_summary() -> dict:
    """Get a brief compliance summary for dashboard display."""
    evaluation = evaluate_policies()
    
    return {
        'overall_status': 'compliant' if evaluation['overall_compliant'] else 'non-compliant',
        'score': f"{evaluation['policies_passed']}/{evaluation['policies_evaluated']}",
        'timestamp': evaluation['timestamp'],
        'failed_policies': [
            {
                'name': r['policy_name'],
                'severity': r.get('policy_severity', 'medium'),
                'message': r['message']
            }
            for r in evaluation['results'] if not r['compliant']
        ]
    }
