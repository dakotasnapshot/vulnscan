"""VulnScan REST API server.

Lightweight HTTP API built on Python's http.server — no external dependencies.
Provides endpoints for host management, scanning, and vulnerability queries.
"""

import base64
import json
import logging
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner import database as db
from scanner.engine import scan_host, scan_all

logger = logging.getLogger("vulnscan.api")

DASHBOARD_DIR = Path(__file__).parent.parent / "dashboard"

# Authentication credentials
AUTH_USERNAME = "admin"
AUTH_PASSWORD = "changeme"


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
            return username == AUTH_USERNAME and password == AUTH_PASSWORD
        except Exception:
            return False

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
            policies = compliance.load_policies_from_db()
            policy_list = [{"policy_id": p.policy_id, "name": p.name, "description": p.description, "severity": p.severity} for p in policies]
            self._send_json(policy_list)
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
                    tags=data.get("tags", [])
                )
                self._send_json({"id": host_id, "status": "created"}, 201)
            except Exception as e:
                self._send_json({"error": str(e)}, 400)

        elif path == "/api/scan":
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
            # Synchronous scan (for API/automation use)
            data = self._read_body()
            host_id = data.get("host_id")
            if host_id:
                result = scan_host(int(host_id))
                self._send_json(result)
            else:
                results = scan_all()
                self._send_json(results)

        else:
            self.send_error(404)

    def do_PUT(self):
        path, _ = self._parse_path()

        # Check authentication
        if not self._check_auth():
            self._require_auth()
            return

        if path.startswith("/api/hosts/") and path.count("/") == 3:
            host_id = int(path.split("/")[3])
            data = self._read_body()
            if "tags" in data and isinstance(data["tags"], list):
                data["tags"] = ",".join(data["tags"])
            db.update_host(host_id, **data)
            self._send_json({"status": "updated"})
        elif path.startswith("/api/vulnerabilities/") and "/status" in path:
            # PATCH /api/vulnerabilities/{id}/status
            vuln_id = int(path.split("/")[3])
            data = self._read_body()
            status = data.get("status")
            if status in ("open", "acknowledged", "fixed", "false_positive"):
                db.update_vuln_status(vuln_id, status)
                self._send_json({"status": "updated"})
            else:
                self._send_json({"error": "Invalid status"}, 400)
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
            host_id = int(path.split("/")[3])
            db.delete_host(host_id)
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
