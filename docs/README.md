# VulnScan 🛡️

A lightweight, self-hosted vulnerability scanner with a web dashboard. Designed for small infrastructure (5-50 hosts) where enterprise tools like Rapid7 or Nessus are overkill.

## Features

- **SSH-based scanning** — No agents to install. Scans remote hosts via SSH.
- **Multi-ecosystem** — Detects OS packages (dpkg/rpm/apk/brew), npm, pip, and Docker containers.
- **OSV.dev integration** — Free vulnerability database, no API key needed.
- **Web dashboard** — Dark-themed, responsive UI with severity breakdown, host overview, and scan history.
- **REST API** — Full API for automation and integration.
- **Lightweight** — Runs in an LXC container with ~200MB RAM. Python + SQLite, no heavy dependencies.

## Quick Start

### Requirements

- Python 3.10+
- `sshpass` (for password-based SSH auth)
- SSH access to target hosts

### Install

```bash
git clone https://github.com/your-org/vulnscan.git
cd vulnscan
# No pip install needed — stdlib only

# Initialize database
python3 -c "from scanner.database import init_db; init_db()"

# Start the server
python3 api/server.py 8080
```

### Add Hosts

Via API:
```bash
curl -X POST http://localhost:8080/api/hosts \
  -H "Content-Type: application/json" \
  -d '{"name": "web-server", "address": "192.168.1.10", "ssh_user": "root", "ssh_password": "secret"}'
```

Or via the web dashboard at `http://localhost:8080`.

### Run a Scan

```bash
# Scan all hosts
curl -X POST http://localhost:8080/api/scan

# Scan specific host
curl -X POST http://localhost:8080/api/scan -d '{"host_id": 1}'

# Synchronous scan (waits for completion)
curl -X POST http://localhost:8080/api/scan/sync
```

### Cron Setup

```bash
# Scan all hosts weekly (Sundays at 2 AM)
echo "0 2 * * 0 cd /opt/vulnscan && python3 scan_cron.py >> /var/log/vulnscan-cron.log 2>&1" | crontab -
```

## Architecture

```
vulnscan/
├── api/
│   └── server.py          # HTTP API + static file server (stdlib only)
├── scanner/
│   ├── engine.py           # Main scan orchestrator
│   ├── database.py         # SQLite data layer
│   ├── osv_client.py       # OSV.dev API client
│   ├── models.py           # Data models
│   └── collectors/
│       ├── ssh.py           # SSH connection helper
│       ├── os_packages.py   # dpkg/rpm/apk/brew collector
│       ├── npm_packages.py  # Node.js package collector
│       ├── pip_packages.py  # Python package collector
│       └── docker_packages.py # Docker container collector
├── dashboard/
│   └── index.html          # Single-page web dashboard
├── db/
│   └── vulnscan.db         # SQLite database (auto-created)
├── scan_cron.py             # CLI wrapper for scheduled scans
└── vulnscan.service         # systemd unit file
```

## API Reference

### Hosts

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/hosts` | List all hosts |
| GET | `/api/hosts/:id` | Get host details |
| POST | `/api/hosts` | Add a host |
| PUT | `/api/hosts/:id` | Update a host |
| DELETE | `/api/hosts/:id` | Delete a host |

### Scanning

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/scan` | Start async scan (all hosts or `host_id`) |
| POST | `/api/scan/sync` | Synchronous scan |

### Vulnerabilities

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/vulnerabilities` | List vulns (filters: `host_id`, `severity`, `status`) |
| PATCH | `/api/vulnerabilities/:id/status` | Update status (open/acknowledged/fixed/false_positive) |

### Other

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/dashboard` | Dashboard summary stats |
| GET | `/api/scans` | Scan history |
| GET | `/api/packages?host_id=X` | Package inventory |
| GET | `/api/health` | Health check |

## Recommended Scan Intervals

| Scan Type | Interval | Rationale |
|-----------|----------|-----------|
| Full scan (all hosts) | Weekly (Sunday 2 AM) | Catches new CVEs without excess load |
| Critical hosts (production) | Daily | Higher exposure = more frequent checks |
| After deployments | On-demand | Catch newly introduced deps |
| After major CVE announcements | On-demand | Like the axios supply chain attack |

## Supported Package Types

| Type | Detection Method | Ecosystem (OSV) |
|------|-----------------|------------------|
| Debian/Ubuntu (dpkg) | `dpkg-query` | Debian, Ubuntu |
| RHEL/CentOS (rpm) | `rpm -qa` | Red Hat |
| Alpine (apk) | `apk list` | Alpine |
| Homebrew (brew) | `brew list --versions` | — (no OSV support) |
| npm (Node.js) | Find `package.json` in node_modules | npm |
| pip (Python) | `pip list --format=freeze` + virtualenvs | PyPI |
| Docker containers | `docker exec` + above methods | Per-container |

## Security Notes

- SSH credentials are stored in SQLite. Restrict access to the database file.
- The API has no authentication by default. Bind to localhost or add a reverse proxy with auth.
- Consider using SSH key auth instead of passwords for production use.

## License

MIT
