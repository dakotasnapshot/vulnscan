#!/bin/bash
# VulnScan Quick Setup Script

set -e

echo "======================================"
echo "   VulnScan Setup"
echo "======================================"
echo

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "[1/5] Checking Python version... $PYTHON_VERSION"
python3 -c 'import sys; assert sys.version_info >= (3, 8), "Python 3.8+ required"' || {
    echo "ERROR: Python 3.8 or higher required"
    exit 1
}

# Check for sshpass
echo "[2/5] Checking for sshpass..."
if ! command -v sshpass &> /dev/null; then
    echo "WARNING: sshpass not found. Password-based SSH auth will not work."
    echo "Install with: apt install sshpass  (Debian/Ubuntu)"
    echo "           or: yum install sshpass  (RHEL/CentOS)"
    echo "           or: brew install hudochenkov/sshpass/sshpass  (macOS)"
else
    echo "  ✓ sshpass found"
fi

# Initialize database
echo "[3/5] Initializing database..."
python3 -c "from scanner import database; database.init_db()" && echo "  ✓ Database initialized"

# Create log directory
echo "[4/5] Creating directories..."
mkdir -p logs
echo "  ✓ Directories created"

# Set permissions
echo "[5/5] Setting permissions..."
chmod +x scan_cron.py 2>/dev/null || true
echo "  ✓ Permissions set"

echo
echo "======================================"
echo "   Setup Complete!"
echo "======================================"
echo
echo "Next steps:"
echo "  1. Change the default password in api/server.py"
echo "  2. Start the API server:"
echo "     python3 api/server.py 8080"
echo "  3. Access the web dashboard:"
echo "     http://localhost:8080"
echo "  4. Default credentials: admin / changeme"
echo
echo "Quick commands:"
echo "  Add a host:"
echo "    curl -u admin:changeme -X POST http://localhost:8080/api/hosts \\"
echo "      -H 'Content-Type: application/json' \\"
echo "      -d '{\"name\": \"server\", \"address\": \"192.168.1.10\", \"ssh_user\": \"root\", \"ssh_password\": \"yourpass\"}'"
echo
echo "  Start a scan:"
echo "    curl -u admin:changeme -X POST http://localhost:8080/api/scan \\"
echo "      -H 'Content-Type: application/json' \\"
echo "      -d '{\"host_id\": 1}'"
echo
echo "Documentation: https://github.com/dakotasnapshot/vulnscan"
echo
