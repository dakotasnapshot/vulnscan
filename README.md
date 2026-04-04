# VulnScan

**Open-source vulnerability scanner for infrastructure and software packages**

VulnScan is a lightweight, zero-dependency Python vulnerability scanner that discovers hosts, inventories software packages, and identifies security vulnerabilities using the OSV.dev database.

## Features

- **Multi-Platform Package Scanning**
  - Operating system packages (dpkg, rpm, apk)
  - Python packages (pip)
  - Node.js packages (npm)
  - Docker container images
  
- **Hypervisor Discovery**
  - Proxmox VE (LXC containers and QEMU VMs)
  - VMware ESXi
  - Automatic guest enumeration and IP detection

- **Network Discovery**
  - Subnet scanning for live hosts
  - Service detection (SSH, HTTP, Proxmox, etc.)
  - OS fingerprinting via SSH banners and authentication
  - Credential testing with configurable profiles

- **Auto-Remediation Framework**
  - Generates fix commands for detected vulnerabilities
  - Supports multiple package managers (apt, yum, apk, brew, pip, npm)
  - Dry-run mode for safe testing
  - Risk assessment for package upgrades
  - Full remediation logging

- **Compliance & Policy Engine**
  - Pre-built policies (no critical vulns >7 days, scan freshness, etc.)
  - Customizable policy definitions
  - Compliance reporting (JSON, CSV)
  - Policy violation tracking

- **REST API & Web Dashboard**
  - RESTful HTTP API (no external dependencies)
  - Real-time scanning via SSH
  - Vulnerability tracking and status updates
  - Host and scan management
  - Basic auth for security

## Architecture

- **Backend**: Pure Python 3 with SQLite database
- **Scanner**: SSH-based remote execution (agentless)
- **Vulnerability Data**: OSV.dev API
- **API**: Python `http.server` (stdlib only)
- **Dashboard**: Static HTML/JS (included)

## Requirements

- Python 3.8+
- SSH access to target hosts
- `sshpass` (for password-based SSH auth)
- Internet access (for OSV.dev API queries)

## Installation

```bash
# Clone the repository
git clone https://github.com/dakotasnapshot/vulnscan.git
cd vulnscan

# No dependencies to install! (stdlib only)

# Initialize the database
python3 -c "from scanner import database; database.init_db()"

# Start the API server
python3 api/server.py 8080
```

Access the web dashboard at `http://localhost:8080`  
Default credentials: `admin` / `VulnScan2026!`

## Quick Start

### Add a host

```bash
curl -u admin:VulnScan2026! -X POST http://localhost:8080/api/hosts \
  -H "Content-Type: application/json" \
  -d '{
    "name": "webserver",
    "address": "192.168.1.10",
    "ssh_user": "root",
    "ssh_password": "YOUR_PASSWORD",
    "tags": ["production", "web"]
  }'
```

### Scan a host

```bash
curl -u admin:VulnScan2026! -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"host_id": 1}'
```

### View vulnerabilities

```bash
curl -u admin:VulnScan2026! http://localhost:8080/api/vulnerabilities
```

## API Endpoints

### Core Operations
- `GET /api/dashboard` — Dashboard statistics
- `GET /api/hosts` — List all hosts
- `POST /api/hosts` — Add a new host
- `POST /api/scan` — Trigger a scan
- `GET /api/vulnerabilities` — List vulnerabilities
- `GET /api/packages` — List discovered packages

### Discovery
- `POST /api/discover` — Trigger network or hypervisor discovery
- `GET /api/discover/results` — Get discovery results

### Remediation
- `POST /api/remediate` — Execute remediation (dry-run or live)
- `GET /api/remediate/history` — View remediation logs

### Compliance
- `GET /api/compliance` — Run compliance check
- `GET /api/compliance/report?format=csv` — Download compliance report
- `GET /api/policies` — List policies

## Configuration

### Database Location
Default: `/opt/vulnscan/db/vulnscan.db`  
Change in `scanner/database.py`:

```python
DB_PATH = Path("/your/custom/path/vulnscan.db")
```

### Authentication
Change credentials in `api/server.py`:

```python
AUTH_USERNAME = "admin"
AUTH_PASSWORD = "your_secure_password"
```

### Scheduled Scanning
Use `scan_cron.py` for automated scans:

```bash
# Add to crontab
0 2 * * * cd /opt/vulnscan && python3 scan_cron.py
```

## Deployment

### SystemD Service

```ini
[Unit]
Description=VulnScan API Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/vulnscan
ExecStart=/usr/bin/python3 /opt/vulnscan/api/server.py 8080
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo cp vulnscan.service /etc/systemd/system/
sudo systemctl enable vulnscan
sudo systemctl start vulnscan
```

## Security Notes

- Change default credentials immediately
- Use SSH keys instead of passwords where possible
- Restrict API access via firewall or reverse proxy
- Run with least privilege (don't run as root if possible)
- Validate all inputs before adding hosts
- This tool executes commands on remote hosts — use responsibly

## Development

### Project Structure

```
vulnscan/
├── api/
│   └── server.py           # REST API server
├── scanner/
│   ├── database.py         # SQLite layer
│   ├── engine.py           # Scan orchestration
│   ├── osv_client.py       # OSV.dev API client
│   ├── models.py           # Data models
│   ├── remediation.py      # Auto-remediation engine
│   ├── compliance.py       # Policy & compliance
│   └── collectors/
│       ├── ssh.py          # SSH helper
│       ├── os_packages.py  # OS package collector
│       ├── pip_packages.py # Python package collector
│       ├── npm_packages.py # Node.js package collector
│       ├── docker_packages.py  # Docker image collector
│       ├── hypervisor.py   # Hypervisor discovery
│       └── network_discovery.py  # Network scanning
├── dashboard/
│   └── index.html          # Web UI
├── db/
│   └── vulnscan.db         # SQLite database
├── scan_cron.py            # Cron job script
└── vulnscan.service        # SystemD unit file
```

### Adding a New Package Collector

1. Create `scanner/collectors/your_collector.py`
2. Implement `collect(host: dict) -> list[dict]`
3. Add to `scanner/engine.py` in the `scan_host()` function

### Adding a New Remediation Strategy

1. Extend `RemediationStrategy` in `scanner/remediation.py`
2. Implement `can_handle()` and `generate_fix_command()`
3. Add to `STRATEGIES` list

## License

MIT License — see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please open an issue or pull request.

## Roadmap

- [ ] Agent-based scanning (optional local agent for better performance)
- [ ] SBOM export (SPDX, CycloneDX)
- [ ] Custom CVE feeds
- [ ] Alerting (email, Slack, webhooks)
- [ ] Multi-user support with RBAC
- [ ] Historical trending and metrics
- [ ] Integration with CI/CD pipelines

## Author

Dakota Cole — [dakota@hawthornmail.com](mailto:dakota@hawthornmail.com)

## Acknowledgments

- [OSV.dev](https://osv.dev) for vulnerability data
- Python standard library for making this dependency-free
- The open-source security community

---

**⚠️ Disclaimer**: This tool performs security scans and can execute commands on remote systems. Always obtain proper authorization before scanning infrastructure you don't own.
