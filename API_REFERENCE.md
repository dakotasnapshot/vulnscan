# VulnScan API Reference

Base URL: `http://localhost:8080`  
Auth: HTTP Basic Auth (default: `admin:changeme`)

---

## Core Endpoints

### GET /api/health
Health check (no auth required)

**Response:**
```json
{"status": "ok", "version": "1.0.0"}
```

### GET /api/dashboard
Dashboard statistics

**Response:**
```json
{
  "total_hosts": 10,
  "total_vulns": 42,
  "critical": 5,
  "high": 12,
  "medium": 20,
  "low": 5,
  "recent_scans": [...],
  "hosts_summary": [...]
}
```

---

## Host Management

### GET /api/hosts
List all hosts

**Response:**
```json
[
  {
    "id": 1,
    "name": "webserver",
    "address": "192.168.1.10",
    "ssh_user": "root",
    "os_family": "linux",
    "os_name": "Ubuntu 22.04",
    "enabled": 1,
    "last_scan": "2026-04-03T20:00:00Z",
    "tags": "production,web"
  }
]
```

### POST /api/hosts
Add a new host

**Request:**
```json
{
  "name": "database-server",
  "address": "192.168.1.20",
  "ssh_user": "root",
  "ssh_password": "secret",
  "ssh_port": 22,
  "tags": ["production", "database"]
}
```

**Response:**
```json
{"id": 2, "status": "created"}
```

### GET /api/hosts/:id
Get a specific host

### DELETE /api/hosts/:id
Delete a host

---

## Scanning

### POST /api/scan
Trigger a scan

**Request:**
```json
{"host_id": 1}
```

**Response:**
```json
{
  "scan_id": 42,
  "status": "started",
  "host_id": 1
}
```

### POST /api/scan/sync
Synchronous scan (waits for completion)

**Request:**
```json
{"host_id": 1}
```

**Response:**
```json
{
  "scan_id": 42,
  "status": "completed",
  "packages_found": 150,
  "vulns_found": 8
}
```

### GET /api/scans?host_id=1&limit=50
List scans

---

## Vulnerabilities

### GET /api/vulnerabilities
List vulnerabilities

**Query params:**
- `host_id` — Filter by host
- `severity` — Filter by severity (critical, high, medium, low)
- `status` — Filter by status (open, fixed, acknowledged)
- `limit` — Max results (default: 500)

**Response:**
```json
[
  {
    "id": 1,
    "cve_id": "CVE-2024-1234",
    "package_name": "openssl",
    "package_version": "1.1.1k",
    "severity": "critical",
    "cvss_score": 9.8,
    "summary": "Remote code execution in OpenSSL",
    "fixed_version": "1.1.1l",
    "host_name": "webserver",
    "status": "open"
  }
]
```

### GET /api/vulnerabilities/:id
Get vulnerability with fix command

**Response:**
```json
{
  "id": 1,
  "cve_id": "CVE-2024-1234",
  "package_name": "openssl",
  "package_version": "1.1.1k",
  "severity": "critical",
  "fix_command": "apt-get install -y --only-upgrade openssl=1.1.1l",
  "fix_strategy": "AptStrategy",
  "fix_risk": "high",
  "fix_description": "Upgrade openssl to 1.1.1l",
  "references": [...]
}
```

### PUT /api/vulnerabilities/:id
Update vulnerability status

**Request:**
```json
{"status": "acknowledged"}
```

---

## Discovery (New)

### POST /api/discover
Trigger discovery

**Request (Subnet Scan):**
```json
{
  "type": "subnet",
  "subnet": "192.168.4.0/24",
  "quick": false,
  "credentials": [
    {"username": "root", "password": "secret"}
  ]
}
```

**Request (Hypervisor Discovery):**
```json
{
  "type": "hypervisor",
  "host_id": 8
}
```

**Response:**
```json
{
  "status": "started",
  "type": "subnet",
  "subnet": "192.168.4.0/24"
}
```

### GET /api/discover/results
Get discovery results

**Response:**
```json
[
  {
    "id": 1,
    "ip": "192.168.4.65",
    "hostname": "homeassistant.local",
    "os_family": "linux",
    "os_name": "Debian 11",
    "services_json": "{\"ssh\": 22, \"http\": 80}",
    "ssh_accessible": true,
    "discovered_at": "2026-04-03T20:00:00Z"
  }
]
```

---

## Remediation (New)

### POST /api/remediate
Execute remediation

**Request (Single Vulnerability):**
```json
{
  "target_type": "vulnerability",
  "vuln_id": 1,
  "dry_run": true
}
```

**Request (All Vulns on Host):**
```json
{
  "target_type": "host",
  "host_id": 1,
  "severity": "critical",
  "dry_run": false
}
```

**Response:**
```json
{
  "vuln_id": 1,
  "host_id": 1,
  "command": "apt-get install -y --only-upgrade openssl=1.1.1l",
  "dry_run": true,
  "success": true,
  "output": "DRY RUN: Would execute: apt-get install...",
  "timestamp": "2026-04-03T20:00:00Z"
}
```

### GET /api/remediate/history?host_id=1&limit=100
Get remediation history

**Response:**
```json
[
  {
    "id": 1,
    "host_id": 1,
    "host_name": "webserver",
    "vuln_id": 1,
    "command": "apt-get install -y --only-upgrade openssl",
    "dry_run": false,
    "success": true,
    "output": "Reading package lists...\nUpgrading openssl...",
    "timestamp": "2026-04-03T19:30:00Z"
  }
]
```

---

## Compliance (New)

### GET /api/compliance
Run compliance check

**Response:**
```json
{
  "timestamp": "2026-04-03T20:00:00Z",
  "overall_compliant": false,
  "policies_evaluated": 4,
  "policies_passed": 2,
  "policies_failed": 2,
  "results": [
    {
      "policy_id": "no-critical-vulns",
      "policy_name": "No Critical Vulnerabilities > 7 Days",
      "compliant": false,
      "message": "5 critical vulnerability(ies) older than 7 days",
      "violations": [...]
    }
  ]
}
```

### GET /api/compliance/report?format=csv
Download compliance report

**Query params:**
- `format` — `json` (default) or `csv`

**Response (CSV):**
```
Policy ID,Policy Name,Compliant,Severity,Message,Violation Count
no-critical-vulns,No Critical Vulns > 7 Days,No,critical,5 vulns found,5
no-high-vulns,No High Vulns > 14 Days,Yes,high,Compliant,0
```

### GET /api/policies
List policies

**Response:**
```json
[
  {
    "policy_id": "no-critical-vulns",
    "name": "No Critical Vulnerabilities > 7 Days",
    "description": "Critical vulns must be remediated within 7 days",
    "severity": "critical"
  }
]
```

### POST /api/policies
Create custom policy (placeholder)

**Status:** 501 Not Implemented (planned for future)

---

## Packages

### GET /api/packages?host_id=1&scan_id=42
List discovered packages

**Response:**
```json
[
  {
    "id": 1,
    "name": "openssl",
    "version": "1.1.1k",
    "pkg_type": "dpkg",
    "ecosystem": "Debian",
    "source_path": "/var/lib/dpkg/status",
    "host_id": 1,
    "scan_id": 42
  }
]
```

---

## Authentication

All endpoints (except /api/health) require HTTP Basic Auth:

```bash
curl -u admin:changeme http://localhost:8080/api/hosts
```

Or with header:
```bash
curl -H "Authorization: Basic YWRtaW46Y2hhbmdlbWU=" http://localhost:8080/api/hosts
```

---

## Error Responses

### 401 Unauthorized
```json
{"error": "Authentication required"}
```

### 404 Not Found
```json
{"error": "Host not found"}
```

### 400 Bad Request
```json
{"error": "host_id required"}
```

### 500 Internal Server Error
```json
{"error": "Scan failed", "details": "..."}
```

---

## Example Workflow

```bash
# 1. Add a host
curl -u admin:changeme -X POST http://localhost:8080/api/hosts \
  -H "Content-Type: application/json" \
  -d '{"name": "web1", "address": "192.168.1.10", "ssh_user": "root", "ssh_password": "secret"}'

# 2. Scan the host
curl -u admin:changeme -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"host_id": 1}'

# 3. View vulnerabilities
curl -u admin:changeme "http://localhost:8080/api/vulnerabilities?host_id=1&severity=critical"

# 4. Get fix command for a vuln
curl -u admin:changeme http://localhost:8080/api/vulnerabilities/1

# 5. Test remediation (dry-run)
curl -u admin:changeme -X POST http://localhost:8080/api/remediate \
  -H "Content-Type: application/json" \
  -d '{"target_type": "vulnerability", "vuln_id": 1, "dry_run": true}'

# 6. Execute remediation (for real)
curl -u admin:changeme -X POST http://localhost:8080/api/remediate \
  -H "Content-Type: application/json" \
  -d '{"target_type": "vulnerability", "vuln_id": 1, "dry_run": false}'

# 7. Check compliance
curl -u admin:changeme http://localhost:8080/api/compliance

# 8. Discover network
curl -u admin:changeme -X POST http://localhost:8080/api/discover \
  -H "Content-Type: application/json" \
  -d '{"type": "subnet", "subnet": "192.168.4.0/24", "quick": true}'

# 9. View discovery results
curl -u admin:changeme http://localhost:8080/api/discover/results
```

---

## Rate Limiting

Currently: None (consider adding for production)

## CORS

Enabled for all origins (`Access-Control-Allow-Origin: *`)

---

**Documentation**: https://github.com/dakotasnapshot/vulnscan  
**Issues**: https://github.com/dakotasnapshot/vulnscan/issues
