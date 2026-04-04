# VulnScan

Lightweight, self-hosted vulnerability management platform. SSH-based package scanning, OSV.dev vulnerability lookup, automated remediation, compliance policies — all in a single-file dashboard with zero external dependencies.

![License](https://img.shields.io/badge/license-MIT-blue.svg)

## Features

### Dashboard
- Real-time vulnerability overview with severity breakdown
- Host risk matrix with drill-down
- One-click **Scan All Hosts** for global assessment
- Recent scan activity feed

### Host Management
- Add hosts individually or bulk-import from network discovery
- SSH credential management with reusable credential profiles
- Per-host scanning with OS detection (Debian/Ubuntu, RHEL/CentOS, Alpine, macOS)
- Edit, enable/disable, and delete hosts

### Vulnerability Scanning
- **Package collection:** OS packages (dpkg/rpm/apk/brew), npm, pip, Docker
- **Vulnerability lookup:** OSV.dev API (free, no API key required)
- **Severity classification:** Critical, High, Medium, Low with CVSS scores
- **Status tracking:** Open, Acknowledged, Fixed, False Positive

### Remediation
- **Per-vulnerability fixes:** Preview the generated command, dry-run, then execute
- **Per-host bulk remediation:** Fix all open vulns on a host in one click
- **Strategy engine:** Auto-selects apt/yum/apk/brew/pip/npm based on OS and package type
- **Risk assessment:** Flags high-risk packages (kernel, systemd, glibc, openssl)
- **Full audit log:** Every remediation action recorded with output

### Network Discovery
- Subnet scanning (CIDR) with optional credential profiles
- Quick mode (ping) or full port scan
- SSH accessibility detection
- Bulk-add discovered hosts

### Compliance
- Built-in policies:
  - No critical vulns older than 7 days
  - No high vulns older than 14 days
  - All hosts scanned within 7 days
  - Total vuln count threshold
- Pass/fail scoring with CSV export
- Extensible policy framework

### Settings
- Credential profile management for SSH access
- Reusable across host provisioning and discovery

## Quick Start

```bash
# Clone
git clone https://github.com/dakotasnapshot/vulnscan.git
cd vulnscan

# Install (sets up Python venv, creates systemd service)
sudo bash setup.sh

# Or run directly
python3 api/server.py

# Set password (default: changeme)
export VULNSCAN_PASSWORD="your-secure-password"

# Open dashboard
open http://localhost:8080
```

## Architecture

```
┌──────────────────────────────────────────────┐
│              Browser Dashboard               │
│  (Single HTML file, vanilla JS, dark theme)  │
└───────────────┬──────────────────────────────┘
                │ HTTP Basic Auth
┌───────────────▼──────────────────────────────┐
│             Python API Server                │
│  (stdlib http.server, no frameworks)         │
├──────────────────────────────────────────────┤
│  Scanner Engine    │  Remediation Engine     │
│  • SSH collectors  │  • Strategy selection   │
│  • OS detection    │  • Dry run / execute    │
│  • Package enum    │  • Risk assessment      │
├────────────────────┤  • Audit logging        │
│  OSV.dev Client    ├─────────────────────────┤
│  • Batch queries   │  Compliance Engine      │
│  • CVE matching    │  • Policy evaluation    │
│  • Severity map    │  • Report generation    │
└───────┬──────────────────────────────────────┘
        │
┌───────▼──────────────────────────────────────┐
│              SQLite Database                 │
│  hosts, scans, packages, vulnerabilities,   │
│  credential_profiles, remediation_log,      │
│  discovery_results                          │
└──────────────────────────────────────────────┘
```

## API

All endpoints require HTTP Basic Auth except `/api/health`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check (no auth) |
| GET | `/api/dashboard` | Dashboard stats + host summary |
| GET/POST | `/api/hosts` | List or add hosts |
| POST | `/api/hosts/bulk` | Bulk add hosts |
| PUT | `/api/hosts/:id` | Update host |
| DELETE | `/api/hosts/:id` | Delete host |
| POST | `/api/scan` | Start scan (single host or all) |
| GET | `/api/scans` | Scan history |
| GET | `/api/vulnerabilities` | List vulns (filterable) |
| PATCH | `/api/vulnerabilities/:id/status` | Update vuln status |
| POST | `/api/remediate/vuln` | Remediate single vuln |
| POST | `/api/remediate/host` | Remediate all vulns on host |
| POST | `/api/remediate/preview` | Preview fix command |
| GET | `/api/remediate/history` | Remediation audit log |
| POST | `/api/discover/subnet` | Subnet discovery |
| GET | `/api/discover/results` | Discovery results |
| GET/POST | `/api/credentials` | Credential profiles |
| GET | `/api/compliance` | Compliance evaluation |
| GET | `/api/compliance/report` | Compliance report (JSON/CSV) |

## Requirements

- Python 3.10+
- SSH access to target hosts
- No external Python dependencies (stdlib only)
- Targets need standard package managers (apt, yum, apk, pip, npm)

## License

MIT
