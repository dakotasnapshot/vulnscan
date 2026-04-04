# VulnScan Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         User Interface                          │
│  ┌──────────────────┐         ┌──────────────────────────────┐ │
│  │  Web Dashboard   │         │   REST API Clients            │ │
│  │  (HTML/JS)       │         │   (curl, scripts, automation) │ │
│  └────────┬─────────┘         └──────────────┬───────────────┘ │
└───────────┼────────────────────────────────────┼────────────────┘
            │                                    │
            └────────────┬───────────────────────┘
                         │ HTTP (Basic Auth)
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                        API Server Layer                         │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  api/server.py                                           │  │
│  │  • HTTP Request Handling (stdlib http.server)           │  │
│  │  • Authentication (Basic Auth)                          │  │
│  │  • Route Handling (GET/POST/PUT/DELETE)                │  │
│  │  • JSON Response Formatting                            │  │
│  └──────────────────────────────────────────────────────────┘  │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Business Logic Layer                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │ scanner/     │  │ scanner/     │  │ scanner/             │ │
│  │ engine.py    │  │ remediation.py│ │ compliance.py        │ │
│  │              │  │              │  │                      │ │
│  │ • Scan       │  │ • Fix Gen    │  │ • Policy Eval        │ │
│  │   Orchestr.  │  │ • Dry-run    │  │ • Report Gen         │ │
│  │ • Package    │  │ • Execute    │  │ • Violation Track    │ │
│  │   Collection │  │ • Risk Assess│  │                      │ │
│  └──────────────┘  └──────────────┘  └──────────────────────┘ │
└───────────────────────────┬─────────────────────────────────────┘
                            │
        ┌───────────────────┼──────────────────┐
        │                   │                  │
        ▼                   ▼                  ▼
┌──────────────┐  ┌──────────────────┐  ┌─────────────────────┐
│  Collectors  │  │  OSV.dev API     │  │  Database Layer     │
│              │  │                  │  │                     │
│ • OS Packages│  │ • CVE Lookup     │  │  scanner/database.py│
│ • Python Pkg │  │ • Vulnerability  │  │                     │
│ • Node Pkg   │  │   Metadata       │  │  • Hosts CRUD       │
│ • Docker Img │  │ • Severity       │  │  • Scans CRUD       │
│ • Hypervisor │  │   Scoring        │  │  • Vulns CRUD       │
│ • Network    │  │                  │  │  • Packages CRUD    │
│   Discovery  │  │                  │  │  • Discovery Logs   │
└──────┬───────┘  └─────────┬────────┘  └──────────┬──────────┘
       │                    │                       │
       │ SSH                │ HTTPS                 │
       ▼                    ▼                       ▼
┌──────────────┐  ┌──────────────────┐  ┌─────────────────────┐
│  Target      │  │  Internet        │  │  SQLite Database    │
│  Hosts       │  │                  │  │                     │
│              │  │  osv.dev         │  │  db/vulnscan.db     │
│ • Linux      │  │                  │  │                     │
│ • macOS      │  │                  │  │  Tables:            │
│ • Containers │  │                  │  │  • hosts            │
│ • VMs        │  │                  │  │  • scans            │
│ • Hypervisors│  │                  │  │  • vulnerabilities  │
└──────────────┘  └──────────────────┘  │  • packages         │
                                        │  • remediation_log  │
                                        │  • discovery_results│
                                        └─────────────────────┘
```

---

## Component Details

### 1. API Server (`api/server.py`)
**Purpose**: HTTP interface for all operations  
**Technology**: Python `http.server` (stdlib)  
**Auth**: HTTP Basic Auth  
**Features**:
- RESTful endpoint routing
- JSON request/response handling
- CORS support
- Static file serving (dashboard)
- Background task spawning (discovery, scanning)

**Key Routes**:
- `/api/hosts` — Host management
- `/api/scan` — Trigger scans
- `/api/vulnerabilities` — Query vulnerabilities
- `/api/discover` — Network/hypervisor discovery
- `/api/remediate` — Execute fixes
- `/api/compliance` — Policy checks

---

### 2. Scan Engine (`scanner/engine.py`)
**Purpose**: Orchestrate vulnerability scans  
**Flow**:
1. Create scan record in DB
2. Detect OS via SSH
3. Run all applicable collectors
4. Query OSV.dev for each package
5. Store packages and vulnerabilities
6. Update scan status

**Collectors Used**:
- `os_packages.py` → dpkg, rpm, apk
- `pip_packages.py` → Python packages
- `npm_packages.py` → Node.js packages
- `docker_packages.py` → Container images

---

### 3. Remediation Engine (`scanner/remediation.py`)
**Purpose**: Generate and execute package upgrades  

**Architecture**:
```
┌─────────────────────────────────────┐
│  RemediationStrategy (Base Class)  │
│  • can_handle(os, pkg_type)        │
│  • generate_fix_command(pkg, ver)  │
│  • assess_risk(pkg)                │
└─────────────────────────────────────┘
              ▲
              │ Inheritance
     ┌────────┴────────┬─────────────┬────────────┐
     │                 │             │            │
┌─────────┐   ┌──────────────┐  ┌─────────┐  ┌─────────┐
│ Apt     │   │ Yum/DNF      │  │ Apk     │  │ Brew    │
│ Strategy│   │ Strategy     │  │ Strategy│  │ Strategy│
└─────────┘   └──────────────┘  └─────────┘  └─────────┘
┌─────────┐   ┌──────────────┐
│ Pip     │   │ Npm          │
│ Strategy│   │ Strategy     │
└─────────┘   └──────────────┘
```

**Workflow**:
1. Identify package type & OS
2. Select appropriate strategy
3. Generate fix command
4. Assess risk (critical packages = high risk)
5. Execute via SSH (or dry-run)
6. Log result to database

**Safety**:
- Dry-run mode by default
- Risk assessment flags critical packages
- Full logging of all actions
- Rollback support (planned)

---

### 4. Compliance Engine (`scanner/compliance.py`)
**Purpose**: Policy evaluation and reporting  

**Policy Types**:
```
Policy (Base Class)
├── NoCriticalVulnsPolicy (max_age_days)
├── NoHighVulnsPolicy (max_age_days)
├── RecentScansPolicy (max_age_days)
└── MaxVulnerabilityCountPolicy (max_count)
```

**Evaluation Flow**:
1. Load policies (built-in or custom)
2. For each policy:
   - Query database for violations
   - Return compliant status + violation list
3. Aggregate results
4. Generate report (JSON or CSV)

**Output**:
- Overall compliance status
- Per-policy pass/fail
- Violation details
- Timestamps

---

### 5. Discovery System

#### Network Discovery (`scanner/collectors/network_discovery.py`)
**Purpose**: Find hosts on a subnet

**Process**:
1. Parse CIDR notation (e.g., 10.0.0.0/24)
2. For each IP:
   - Ping test
   - TCP port scan (SSH, HTTP, HTTPS, Proxmox, RDP, VNC)
   - Hostname resolution (reverse DNS)
   - SSH banner grab
   - Credential testing (if provided)
3. Store results in `discovery_results` table

**Data Collected**:
- IP address
- Hostname
- OS family & name
- Open ports/services
- SSH accessibility

#### Hypervisor Discovery (`scanner/collectors/hypervisor.py`)
**Purpose**: Enumerate VMs/containers from hypervisors

**Supported Platforms**:
- **Proxmox VE**:
  - Detection: Check for `pvesh`, `pct`, `qm`
  - LXC: `pct list` + `pct exec <id> hostname -I`
  - QEMU: `qm list` + `qm guest cmd <id> network-get-interfaces`
  
- **VMware ESXi**:
  - Detection: Check for `vim-cmd`, `esxcli`
  - VMs: `vim-cmd vmsvc/getallvms`
  - Power state: `vim-cmd vmsvc/power.getstate`
  - IPs: `vim-cmd vmsvc/get.guest`

**Output**:
- Guest type (lxc, qemu, vmware-vm)
- VMID
- Name
- Status (running, stopped)
- IP address
- Parent hypervisor

---

### 6. Database Layer (`scanner/database.py`)
**Purpose**: SQLite ORM and data persistence

**Schema**:
```sql
-- Core Tables
hosts              (id, name, address, ssh_*, os_*, tags, ...)
scans              (id, host_id, started_at, finished_at, status, ...)
packages           (id, name, version, pkg_type, host_id, scan_id, ...)
vulnerabilities    (id, cve_id, package_*, severity, status, ...)

-- New Tables
remediation_log    (id, host_id, vuln_id, command, success, ...)
discovery_results  (id, ip, hostname, os_*, services_json, ...)
```

**Functions**:
- CRUD for hosts, scans, packages, vulnerabilities
- `get_dashboard_stats()` — Aggregated metrics
- `get_vulnerability_with_fix()` — Enrich with remediation
- `log_remediation_action()` — Audit trail
- `get_remediation_history()` — Query logs

**Features**:
- Row factory (dict access)
- Foreign keys enforced
- Indexes on common queries
- WAL mode for performance
- Automatic init on import

---

### 7. Collectors (`scanner/collectors/`)

#### SSH Collector (`ssh.py`)
**Purpose**: Execute commands on remote hosts

**Functions**:
- `ssh_exec(host, command, timeout)` → (returncode, stdout, stderr)
- `detect_os(host)` → (os_family, os_name)

**Features**:
- Password auth via `sshpass`
- Key-based auth support
- Timeout handling
- Error logging
- StrictHostKeyChecking disabled (for automation)

#### OS Packages (`os_packages.py`)
**Purpose**: Inventory system packages

**Supported**:
- **Debian/Ubuntu**: `dpkg-query -W`
- **RHEL/CentOS**: `rpm -qa`
- **Alpine**: `apk info -v`

**Output**: List of (name, version, pkg_type, ecosystem)

#### Python Packages (`pip_packages.py`)
**Purpose**: Inventory Python packages

**Methods**:
- `pip list --format=json` (global)
- `pip freeze` (virtualenvs)
- Parse `requirements.txt`

#### Node.js Packages (`npm_packages.py`)
**Purpose**: Inventory npm packages

**Methods**:
- `npm list --json --depth=0`
- Parse `package-lock.json`

#### Docker Images (`docker_packages.py`)
**Purpose**: Scan container images

**Methods**:
- `docker images --format json`
- Image layer inspection
- Package extraction from images

---

## Data Flow

### Scan Workflow
```
User Request → API Server → Scan Engine
                              ↓
                    Create scan record (DB)
                              ↓
                    SSH to target host
                              ↓
                    Detect OS
                              ↓
              ┌────────────────┴────────────────┐
              │   Run Collectors (parallel)     │
              │   • OS Packages                 │
              │   • Python Packages             │
              │   • Node Packages               │
              │   • Docker Images               │
              └────────────────┬────────────────┘
                              ↓
                    Store packages (DB)
                              ↓
          ┌──────────────────────────────────┐
          │  For each package:               │
          │  1. Query OSV.dev API            │
          │  2. Get vulnerabilities          │
          │  3. Store to DB                  │
          └──────────────────────────────────┘
                              ↓
                    Update scan status (DB)
                              ↓
                    Return results → User
```

### Remediation Workflow
```
User Request → API Server → Remediation Engine
                              ↓
                Get vulnerability from DB
                              ↓
                Get host info from DB
                              ↓
        Select strategy (based on OS + pkg type)
                              ↓
            Generate fix command
                              ↓
            Assess risk
                              ↓
       ┌────────────────────────────────┐
       │  if dry_run:                   │
       │    Return preview              │
       │  else:                         │
       │    SSH exec fix command        │
       │    Log result to DB            │
       └────────────────────────────────┘
                              ↓
                    Return result → User
```

### Discovery Workflow
```
User Request → API Server
       ↓
  Discovery Type?
       ↓
  ┌────────────────────────┐
  │   Subnet               │   Hypervisor
  │                        │        │
  │  Parse CIDR            │   Get host from DB
  │  For each IP:          │        ↓
  │    • Ping              │   SSH to hypervisor
  │    • Port scan         │        ↓
  │    • OS detect         │   Detect type (Proxmox/ESXi)
  │    • Credential test   │        ↓
  │  Store results (DB)    │   Enumerate guests
  │                        │   Get IPs
  └────────────────────────┘   Store results (DB)
                              ↓
                    Return results → User
```

---

## Security Architecture

### Authentication
- HTTP Basic Auth on all endpoints (except /health)
- Credentials configurable in `api/server.py`
- Base64 encoded in Authorization header
- No session management (stateless)

### Authorization
- Currently: single admin user
- Future: RBAC with user roles

### Data Protection
- SSH passwords stored in plaintext (DB encryption planned)
- Database file permissions (600)
- SQL injection prevention (parameterized queries)
- Command injection prevention (SSH command escaping)

### Network Security
- API binds to 0.0.0.0 (configure for localhost only in production)
- CORS enabled (restrict in production)
- HTTPS not built-in (use reverse proxy)

---

## Scalability

### Current Limits
- Single-threaded API server
- Synchronous scanning (one host at a time)
- SQLite (not suited for >1000 hosts)
- In-memory discovery results

### Scaling Options
1. **Horizontal**: Run multiple scanner instances
2. **Vertical**: Parallel scan workers (threading/async)
3. **Database**: Migrate to PostgreSQL
4. **Caching**: Redis for scan results
5. **Queue**: Celery for background jobs

---

## Dependencies

### External (Optional)
- `sshpass` — Password-based SSH auth

### Python Stdlib Only
- `http.server` — API server
- `sqlite3` — Database
- `subprocess` — SSH execution
- `json` — Data serialization
- `socket` — Network scanning
- `ipaddress` — CIDR parsing
- `threading` — Background tasks
- `logging` — Audit trail

**Total PyPI dependencies**: 0 🎉

---

## Deployment Modes

### 1. Standalone (Development)
```
python3 api/server.py 8080
```

### 2. SystemD Service (Production)
```ini
[Service]
ExecStart=/usr/bin/python3 /opt/vulnscan/api/server.py 8080
```

### 3. Container (Docker/LXC)
```dockerfile
FROM python:3.10-slim
COPY . /app
CMD ["python3", "/app/api/server.py", "8080"]
```

### 4. Reverse Proxy (Nginx + HTTPS)
```nginx
location /vulnscan/ {
    proxy_pass http://localhost:8080/;
}
```

---

## Performance Characteristics

### Scan Time
- **Small host** (50 packages): ~10 seconds
- **Medium host** (500 packages): ~60 seconds
- **Large host** (2000 packages): ~4 minutes

**Bottleneck**: OSV.dev API queries (1 per package)

### Remediation Time
- **Dry-run**: Instant
- **Single package**: 10-30 seconds (apt/yum download + install)
- **Bulk remediation**: Linear (N × 30 seconds)

### Discovery Time
- **Subnet /24** (quick): ~5 minutes (254 IPs × 1s ping)
- **Subnet /24** (full): ~30 minutes (SSH + port scan)
- **Hypervisor**: ~10 seconds per guest

---

## Monitoring & Observability

### Logs
- API requests (stdout)
- Scan errors (stderr)
- Remediation actions (database)

### Metrics (Future)
- Scan success rate
- Average scan duration
- Vulnerability trends
- Compliance score over time

### Alerts (Future)
- New critical vulnerabilities
- Policy violations
- Scan failures

---

## Extensibility Points

### Add a New Package Type
1. Create `scanner/collectors/your_collector.py`
2. Implement `collect(host: dict) -> list[dict]`
3. Add to `scanner/engine.py`

### Add a New Remediation Strategy
1. Extend `RemediationStrategy` in `remediation.py`
2. Implement `can_handle()` and `generate_fix_command()`
3. Add to `STRATEGIES` list

### Add a Custom Policy
1. Extend `Policy` in `compliance.py`
2. Implement `evaluate()` method
3. Add to `DEFAULT_POLICIES`

### Add a New Discovery Method
1. Add function to `network_discovery.py` or `hypervisor.py`
2. Add API endpoint in `server.py`
3. Store results in `discovery_results` table

---

**This architecture is designed to be simple, maintainable, and production-ready while maintaining zero external dependencies.**
