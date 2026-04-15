"""VulnScan REST API server.

Lightweight HTTP API built on Python's http.server — no external dependencies.
Provides endpoints for host management, scanning, and vulnerability queries.
"""

import base64
import json
import logging
import sys
import threading
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner import database as db
from scanner.engine import scan_host, scan_all

logger = logging.getLogger("vulnscan.api")

DASHBOARD_DIR = Path(__file__).parent.parent / "dashboard"

def _estimate_next_run(cron_expr: str) -> str | None:
    parts = cron_expr.split()
    if len(parts) != 5:
        return None
    minute, hour, dom, month, dow = parts
    if dom != '*' or month != '*' or dow != '*':
        return None
    if minute.startswith('*/') and hour == '*':
        try:
            every = int(minute[2:])
            now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
            next_run = now + timedelta(minutes=every - (now.minute % every or every))
            return next_run.isoformat()
        except Exception:
            return None
    if minute.isdigit() and hour.isdigit():
        now = datetime.now(timezone.utc)
        next_run = now.replace(hour=int(hour), minute=int(minute), second=0, microsecond=0)
        if next_run <= now:
            next_run += timedelta(days=1)
        return next_run.isoformat()
    return None


class VulnScanHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the VulnScan API."""

    def log_message(self, format, *args):
        logger.info(f"{self.client_address[0]} - {format % args}")

    def _check_auth(self) -> bool:
        """Verify HTTP Basic Auth credentials."""
        auth_header = self.headers.get("Authorization", "")
        
        if not auth_header.startswith("Basic "):
            return False
        
        try:
            # Decode base64 credentials
            credentials = base64.b64decode(auth_header[6:]).decode("utf-8")
            username, password = credentials.split(":", 1)
            user = db.authenticate_user(username, password)
            self.current_user = user
            return user is not None
        except Exception:
            return False

    def _require_role(self, *roles):
        user = getattr(self, 'current_user', None)
        if not user or user.get('role') not in roles:
            self._send_json({"error": "Forbidden"}, 403)
            return False
        return True

    def _require_auth(self):
        """Send 401 Unauthorized response with WWW-Authenticate header."""
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="VulnScan"')
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"error": "Authentication required"}).encode())

    def _send_json(self, data, status=200):
        body = json.dumps(data, indent=2, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, filepath: Path, content_type: str):
        if not filepath.exists():
            self.send_error(404)
            return
        data = filepath.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", len(data))
        self.end_headers()
        self.wfile.write(data)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        body = self.rfile.read(length)
        return json.loads(body)

    def _parse_path(self) -> tuple[str, dict]:
        parsed = urlparse(self.path)
        params = {k: v[0] if len(v) == 1 else v
                  for k, v in parse_qs(parsed.query).items()}
        return parsed.path, params

    # --- Routing ---

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        path, params = self._parse_path()

        # Allow /api/health without auth (for monitoring)
        if path == "/api/health":
            self._send_json({"status": "ok", "version": "1.0.0"})
            return

        # Check authentication for all other routes
        if not self._check_auth():
            self._require_auth()
            return

        # Dashboard static files
        if path == "/" or path == "/index.html":
            self._send_file(DASHBOARD_DIR / "index.html", "text/html")
            return
        if path.startswith("/static/"):
            filename = path[8:]  # strip /static/
            ext_map = {".js": "application/javascript", ".css": "text/css",
                       ".png": "image/png", ".svg": "image/svg+xml"}
            ext = Path(filename).suffix
            self._send_file(DASHBOARD_DIR / filename, ext_map.get(ext, "application/octet-stream"))
            return

        # API endpoints
        if path == "/api/dashboard":
            self._send_json(db.get_dashboard_stats())
        elif path == "/api/hosts":
            self._send_json(db.list_hosts())
        elif path.startswith("/api/hosts/") and path.count("/") == 3:
            host_id = int(path.split("/")[3])
            host = db.get_host(host_id)
            if host:
                self._send_json(host)
            else:
                self._send_json({"error": "Host not found"}, 404)
        elif path.startswith("/api/hosts/") and path.endswith("/details"):
            host_id = int(path.split("/")[3])
            host = db.get_host(host_id)
            if not host:
                self._send_json({"error": "Host not found"}, 404)
                return

            scans = db.list_scans(host_id=host_id, limit=10)
            vulns = db.get_vulnerabilities(host_id=host_id, limit=100)
            latest_scan_id = scans[0]["id"] if scans else None
            packages = db.get_packages(host_id, latest_scan_id) if latest_scan_id else []
            facts = db.get_device_facts(host_id, limit=100)

            self._send_json({
                "host": host,
                "device_facts": facts,
                "scans": scans,
                "packages": packages,
                "vulnerabilities": vulns,
            })
        elif path == "/api/scans":
            host_id = params.get("host_id")
            limit = int(params.get("limit", 50))
            self._send_json(db.list_scans(
                host_id=int(host_id) if host_id else None,
                limit=limit
            ))
        elif path.startswith("/api/scans/") and path.count("/") == 3:
            scan_id = int(path.split("/")[3])
            scan = db.get_scan(scan_id)
            if scan:
                self._send_json(scan)
            else:
                self._send_json({"error": "Scan not found"}, 404)
        elif path == "/api/vulnerabilities":
            host_id = params.get("host_id")
            severity = params.get("severity")
            status = params.get("status")
            limit = int(params.get("limit", 500))
            self._send_json(db.get_vulnerabilities(
                host_id=int(host_id) if host_id else None,
                severity=severity,
                status=status,
                limit=limit
            ))
        elif path == "/api/packages":
            host_id = params.get("host_id")
            scan_id = params.get("scan_id")
            if host_id and scan_id:
                pkgs = db.get_packages(int(host_id), int(scan_id))
            elif host_id:
                pkgs = db.get_packages(int(host_id))
            else:
                self._send_json({"error": "host_id required"}, 400)
                return
            self._send_json(pkgs)

        elif path == "/api/credentials":
            self._send_json(db.list_credential_profiles())
        elif path == "/api/users":
            if not self._require_role('admin'):
                return
            self._send_json(db.list_users())
        elif path.startswith("/api/credentials/") and path.count("/") == 3:
            profile_id = int(path.split("/")[3])
            profile = db.get_credential_profile(profile_id)
            if profile:
                self._send_json(profile)
            else:
                self._send_json({"error": "Credential profile not found"}, 404)
        elif path == "/api/discover":
            self._send_json({"error": "Use POST to trigger discovery"}, 405)
        elif path == "/api/discover/results":
            conn = db.get_db()
            rows = conn.execute("SELECT * FROM discovery_results ORDER BY discovered_at DESC LIMIT 100").fetchall()
            conn.close()
            self._send_json([dict(r) for r in rows])
        elif path == "/api/remediate/history":
            from scanner import remediation
            host_id = int(params.get("host_id", 0)) if "host_id" in params else None
            limit = int(params.get("limit", 100))
            history = remediation.get_remediation_history(host_id=host_id, limit=limit)
            self._send_json(history)
        elif path == "/api/schedules":
            self._send_json(db.list_scan_schedules())
        elif path == "/api/auth/me":
            self._send_json({"user": getattr(self, 'current_user', None)})
        elif path == "/api/compliance":
            from scanner import compliance
            result = compliance.evaluate_policies()
            self._send_json(result)
        elif path == "/api/compliance/report":
            from scanner import compliance
            format_type = params.get("format", "json")
            report = compliance.generate_compliance_report(format=format_type)
            if format_type == "csv":
                self.send_response(200)
                self.send_header("Content-Type", "text/csv")
                self.send_header("Content-Disposition", "attachment; filename=compliance_report.csv")
                self.end_headers()
                self.wfile.write(report.encode())
                return
            else:
                self._send_json({"report": report})
        elif path == "/api/policies":
            from scanner import compliance
            self._send_json(compliance.get_policy_catalog())
        elif path.startswith("/api/vulnerabilities/") and "/fix" not in path and path.count("/") == 3:
            vuln_id = int(path.split("/")[3])
            vuln = db.get_vulnerability_with_fix(vuln_id)
            if vuln:
                self._send_json(vuln)
            else:
                self.send_error(404)
                return
            host_id = params.get("host_id")
            scan_id = params.get("scan_id")
            if host_id:
                self._send_json(db.get_packages(
                    int(host_id),
                    scan_id=int(scan_id) if scan_id else None
                ))
            else:
                self._send_json({"error": "host_id required"}, 400)
        else:
            self.send_error(404)

    def do_POST(self):
        path, params = self._parse_path()

        # Check authentication (no exceptions for POST)
        if not self._check_auth():
            self._require_auth()
            return

        if path == "/api/hosts":
            if not self._require_role('admin', 'operator'):
                return
            data = self._read_body()
            required = ["name", "address"]
            if not all(k in data for k in required):
                self._send_json({"error": "name and address required"}, 400)
                return
            try:
                host_id = db.add_host(
                    name=data["name"],
                    address=data["address"],
                    ssh_user=data.get("ssh_user", "root"),
                    ssh_password=data.get("ssh_password"),
                    ssh_key_path=data.get("ssh_key_path"),
                    ssh_port=data.get("ssh_port", 22),
                    tags=data.get("tags", []),
                    platform=data.get("platform", ""),
                    vendor=data.get("vendor", ""),
                    device_type=data.get("device_type", ""),
                    version=data.get("version", ""),
                    snmp_community=data.get("snmp_community"),
                    snmp_version=data.get("snmp_version", "2c"),
                    snmp_port=data.get("snmp_port", 161),
                    snmp_sysdescr=data.get("snmp_sysdescr", ""),
                    snmp_sysobjectid=data.get("snmp_sysobjectid", "")
                )
                self._send_json({"id": host_id, "status": "created"}, 201)
            except Exception as e:
                self._send_json({"error": str(e)}, 400)

        elif path == "/api/scan":
            if not self._require_role('admin', 'operator'):
                return
            data = self._read_body()
            host_id = data.get("host_id")
            if host_id:
                # Scan single host in background
                def _scan():
                    result = scan_host(int(host_id))
                    logger.info(f"Background scan completed: {result}")
                t = threading.Thread(target=_scan, daemon=True)
                t.start()
                self._send_json({"status": "scan_started", "host_id": host_id})
            else:
                # Scan all
                def _scan_all():
                    results = scan_all()
                    logger.info(f"Background scan-all completed: {len(results)} hosts")
                t = threading.Thread(target=_scan_all, daemon=True)
                t.start()
                self._send_json({"status": "scan_all_started"})

        elif path == "/api/scan/sync":
            if not self._require_role('admin', 'operator'):
                return
            # Synchronous scan (for API/automation use)
            data = self._read_body()
            host_id = data.get("host_id")
            if host_id:
                result = scan_host(int(host_id))
                self._send_json(result)
            else:
                results = scan_all()
                self._send_json(results)

        elif path == "/api/hosts/bulk":
            if not self._require_role('admin', 'operator'):
                return
            # Bulk add hosts
            data = self._read_body()
            hosts = data.get("hosts", [])
            credential_profile_id = data.get("credential_profile_id")
            
            if not hosts:
                self._send_json({"error": "hosts array required"}, 400)
                return
            
            try:
                host_ids = db.bulk_add_hosts(hosts, credential_profile_id)
                self._send_json({
                    "status": "created",
                    "count": len(host_ids),
                    "host_ids": host_ids
                }, 201)
            except Exception as e:
                self._send_json({"error": str(e)}, 400)

        elif path == "/api/credentials":
            if not self._require_role('admin'):
                return
            # Create credential profile
            data = self._read_body()
            required = ["name", "ssh_user"]
            if not all(k in data for k in required):
                self._send_json({"error": "name and ssh_user required"}, 400)
                return
            
            try:
                profile_id = db.add_credential_profile(
                    name=data["name"],
                    ssh_user=data["ssh_user"],
                    ssh_password=data.get("ssh_password"),
                    ssh_key_path=data.get("ssh_key_path")
                )
                self._send_json({"id": profile_id, "status": "created"}, 201)
            except Exception as e:
                self._send_json({"error": str(e)}, 400)

        elif path == "/api/discover/subnet":
            if not self._require_role('admin', 'operator'):
                return
            # Subnet discovery
            data = self._read_body()
            subnet = data.get("subnet")
            quick = data.get("quick", False)
            credential_profile_id = data.get("credential_profile_id")
            snmp_community = data.get("snmp_community")
            snmp_version = data.get("snmp_version", "2c")
            snmp_port = data.get("snmp_port", 161)
            auto_add = data.get("auto_add", False)
            auto_scan = data.get("auto_scan", False)
            
            if not subnet:
                self._send_json({"error": "subnet required"}, 400)
                return
            
            # Get credentials if profile specified
            credentials = None
            if credential_profile_id:
                profile = db.get_credential_profile(int(credential_profile_id))
                if profile:
                    credentials = [{
                        'username': profile['ssh_user'],
                        'password': profile.get('ssh_password'),
                        'key_path': profile.get('ssh_key_path')
                    }]
            
            # Run discovery in background
            def _discover():
                from scanner.collectors.network_discovery import scan_subnet
                results = scan_subnet(
                    subnet,
                    credentials=credentials,
                    quick=quick,
                    snmp_community=snmp_community,
                    snmp_version=snmp_version,
                    snmp_port=snmp_port,
                )
                upserted = []
                if auto_add:
                    for host in results:
                        host_id, status = db.upsert_discovered_host(host, credential_profile_id=credential_profile_id)
                        upserted.append({"host_id": host_id, "status": status, "address": host["address"]})
                    logger.info(f"Discovery auto-add completed: {len(upserted)} hosts upserted")
                if auto_scan:
                    host_ids = [entry["host_id"] for entry in upserted] if upserted else []
                    if not host_ids:
                        for host in results:
                            existing = db.get_host_by_address(host["address"])
                            if existing:
                                host_ids.append(existing["id"])
                    for host_id in sorted(set(host_ids)):
                        try:
                            result = scan_host(int(host_id))
                            logger.info(f"Discovery auto-scan completed for host {host_id}: {result}")
                        except Exception as e:
                            logger.error(f"Discovery auto-scan failed for host {host_id}: {e}")
                logger.info(f"Discovery completed: {len(results)} hosts found")
            
            t = threading.Thread(target=_discover, daemon=True)
            t.start()
            
            # Also run synchronously for immediate results
            from scanner.collectors.network_discovery import scan_subnet
            results = scan_subnet(
                subnet,
                credentials=credentials,
                quick=quick,
                snmp_community=snmp_community,
                snmp_version=snmp_version,
                snmp_port=snmp_port,
            )
            upserted = []
            if auto_add:
                for host in results:
                    host_id, status = db.upsert_discovered_host(host, credential_profile_id=credential_profile_id)
                    upserted.append({"host_id": host_id, "status": status, "address": host["address"]})
            scan_started = []
            if auto_scan:
                host_ids = [entry["host_id"] for entry in upserted] if upserted else []
                if not host_ids:
                    for host in results:
                        existing = db.get_host_by_address(host["address"])
                        if existing:
                            host_ids.append(existing["id"])
                for host_id in sorted(set(host_ids)):
                    t = threading.Thread(target=scan_host, args=(int(host_id),), daemon=True)
                    t.start()
                    scan_started.append({"host_id": host_id, "status": "scan_started"})
            self._send_json({
                "status": "completed",
                "hosts": results,
                "upserted": upserted,
                "scan_started": scan_started,
            })

        elif path == "/api/discover/hypervisor":
            if not self._require_role('admin', 'operator'):
                return
            # Hypervisor discovery
            data = self._read_body()
            host_id = data.get("host_id")
            
            if not host_id:
                self._send_json({"error": "host_id required"}, 400)
                return
            
            from scanner.collectors.hypervisor import discover_all_guests
            host = db.get_host(int(host_id))
            
            if not host:
                self._send_json({"error": "Host not found"}, 404)
                return
            
            try:
                result = discover_all_guests(host)
                self._send_json({"status": "completed", "guests": result['guests']})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

        elif path == "/api/schedules":
            if not self._require_role('admin'):
                return
            data = self._read_body()
            name = data.get("name")
            cron_expr = data.get("cron_expr")
            host_id = data.get("host_id")
            enabled = data.get("enabled", True)
            if not name or not cron_expr:
                self._send_json({"error": "name and cron_expr required"}, 400)
                return
            next_run = _estimate_next_run(cron_expr)
            schedule_id = db.add_scan_schedule(
                name=name,
                cron_expr=cron_expr,
                host_id=int(host_id) if host_id else None,
                enabled=enabled,
                next_run=next_run,
            )
            self._send_json({"id": schedule_id, "status": "created", "next_run": next_run}, 201)

        elif path == "/api/schedules/run":
            if not self._require_role('admin', 'operator'):
                return
            data = self._read_body()
            schedule_id = data.get("schedule_id")
            if not schedule_id:
                self._send_json({"error": "schedule_id required"}, 400)
                return
            schedule = db.get_scan_schedule(int(schedule_id))
            if not schedule:
                self._send_json({"error": "Schedule not found"}, 404)
                return
            if schedule.get("host_id"):
                t = threading.Thread(target=scan_host, args=(int(schedule["host_id"]),), daemon=True)
                t.start()
            else:
                t = threading.Thread(target=scan_all, daemon=True)
                t.start()
            db.update_scan_schedule(int(schedule_id), last_run=datetime.now(timezone.utc).isoformat())
            self._send_json({"status": "started", "schedule_id": schedule_id})

        elif path == "/api/policies/settings":
            if not self._require_role('admin'):
                return
            from scanner import database as policy_db
            data = self._read_body()
            policy_id = data.get("policy_id")
            if not policy_id:
                self._send_json({"error": "policy_id required"}, 400)
                return
            enabled = data.get("enabled", True)
            threshold = data.get("threshold")
            policy_db.upsert_policy_setting(
                policy_id=policy_id,
                enabled=enabled,
                threshold=int(threshold) if threshold not in (None, "") else None,
            )
            self._send_json({"status": "updated", "policy_id": policy_id})

        elif path == "/api/users":
            if not self._require_role('admin'):
                return
            data = self._read_body()
            username = data.get('username')
            password = data.get('password')
            role = data.get('role', 'viewer')
            enabled = data.get('enabled', True)
            if not username or not password:
                self._send_json({"error": "username and password required"}, 400)
                return
            user_id = db.create_user(username=username, password=password, role=role, enabled=enabled)
            self._send_json({"id": user_id, "status": "created"}, 201)

        elif path == "/api/auth/change-password":
            data = self._read_body()
            user = getattr(self, 'current_user', None)
            if not user:
                self._send_json({"error": "Authentication required"}, 401)
                return
            new_password = data.get('new_password')
            if not new_password:
                self._send_json({"error": "new_password required"}, 400)
                return
            db.update_user(user['id'], password=new_password)
            self._send_json({"status": "updated"})

        else:
            self.send_error(404)

    def do_PUT(self):
        path, _ = self._parse_path()

        # Check authentication
        if not self._check_auth():
            self._require_auth()
            return

        if path.startswith("/api/hosts/") and path.count("/") == 3:
            if not self._require_role('admin', 'operator'):
                return
            host_id = int(path.split("/")[3])
            data = self._read_body()
            if "tags" in data and isinstance(data["tags"], list):
                data["tags"] = ",".join(data["tags"])
            db.update_host(host_id, **data)
            self._send_json({"status": "updated"})
        elif path.startswith("/api/vulnerabilities/") and "/status" in path:
            if not self._require_role('admin', 'operator'):
                return
            # PATCH /api/vulnerabilities/{id}/status
            vuln_id = int(path.split("/")[3])
            data = self._read_body()
            status = data.get("status")
            if status in ("open", "acknowledged", "fixed", "false_positive"):
                db.update_vuln_status(vuln_id, status)
                self._send_json({"status": "updated"})
            else:
                self._send_json({"error": "Invalid status"}, 400)
        elif path.startswith("/api/schedules/") and path.count("/") == 3:
            if not self._require_role('admin'):
                return
            schedule_id = int(path.split("/")[3])
            data = self._read_body()
            if "enabled" in data:
                data["enabled"] = 1 if data["enabled"] else 0
            if "cron_expr" in data:
                data["next_run"] = _estimate_next_run(data["cron_expr"])
            db.update_scan_schedule(schedule_id, **data)
            self._send_json({"status": "updated"})
        elif path.startswith("/api/users/") and path.count("/") == 3:
            if not self._require_role('admin'):
                return
            user_id = int(path.split("/")[3])
            data = self._read_body()
            db.update_user(user_id, **data)
            self._send_json({"status": "updated"})
        else:
            self.send_error(404)

    def do_PATCH(self):
        # Route PATCH to PUT handler
        self.do_PUT()

    def do_DELETE(self):
        path, _ = self._parse_path()

        # Check authentication
        if not self._check_auth():
            self._require_auth()
            return

        if path.startswith("/api/hosts/") and path.count("/") == 3:
            if not self._require_role('admin'):
                return
            host_id = int(path.split("/")[3])
            db.delete_host(host_id)
            self._send_json({"status": "deleted"})
        elif path.startswith("/api/credentials/") and path.count("/") == 3:
            if not self._require_role('admin'):
                return
            profile_id = int(path.split("/")[3])
            db.delete_credential_profile(profile_id)
            self._send_json({"status": "deleted"})
        elif path.startswith("/api/schedules/") and path.count("/") == 3:
            if not self._require_role('admin'):
                return
            schedule_id = int(path.split("/")[3])
            db.delete_scan_schedule(schedule_id)
            self._send_json({"status": "deleted"})
        else:
            self.send_error(404)


def run_server(host: str = "0.0.0.0", port: int = 8080):
    """Start the VulnScan API server."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    db.init_db()

    server = HTTPServer((host, port), VulnScanHandler)
    logger.info(f"VulnScan API listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port=port)
