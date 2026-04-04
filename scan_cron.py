#!/usr/bin/env python3
"""Cron wrapper for scheduled scans.

Usage:
    python3 scan_cron.py              # Scan all enabled hosts
    python3 scan_cron.py --host 1     # Scan specific host
"""

import sys
import json
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from scanner.engine import scan_host, scan_all

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)


def main():
    if "--host" in sys.argv:
        idx = sys.argv.index("--host")
        host_id = int(sys.argv[idx + 1])
        result = scan_host(host_id)
        print(json.dumps(result, indent=2))
    else:
        results = scan_all()
        for r in results:
            print(json.dumps(r, indent=2))

        # Summary
        total_vulns = sum(r.get("vulns_found", 0) for r in results)
        critical = sum(r.get("by_severity", {}).get("critical", 0) for r in results)
        high = sum(r.get("by_severity", {}).get("high", 0) for r in results)
        print(f"\n--- Scan Summary ---")
        print(f"Hosts scanned: {len(results)}")
        print(f"Total vulns: {total_vulns} (Critical: {critical}, High: {high})")


if __name__ == "__main__":
    main()
