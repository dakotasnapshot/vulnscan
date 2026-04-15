"""RouterOS collector and vulnerability matcher.

This module is built to consume SNMP-derived device metadata. The first version
accepts host metadata already stored in the DB and turns RouterOS version info
into a pseudo-package plus advisory matches from a local feed.
"""

from __future__ import annotations

import json
from typing import Any

from ..routeros_feed import match_routeros_version


MIKROTIK_HINTS = ("mikrotik", "routeros", "routerboard")


def infer_routeros_device(host: dict[str, Any]) -> bool:
    haystack = " ".join(
        str(host.get(k, "")) for k in [
            "os_family", "os_name", "platform", "vendor", "device_type",
            "snmp_sysdescr", "snmp_sysobjectid", "tags"
        ]
    ).lower()
    return any(hint in haystack for hint in MIKROTIK_HINTS)


def collect_routeros_packages(host: dict[str, Any]) -> list[dict[str, Any]]:
    version = host.get("version") or host.get("routeros_version") or ""
    if not version:
        return []

    return [{
        "name": "routeros",
        "version": str(version),
        "pkg_type": "firmware",
        "ecosystem": "RouterOS",
        "source_path": host.get("snmp_sysdescr", "snmp"),
    }]


def match_routeros_vulnerabilities(host: dict[str, Any], scan_id: int) -> list[dict[str, Any]]:
    version = host.get("version") or host.get("routeros_version") or ""
    if not version:
        return []

    vulns = []
    for advisory in match_routeros_version(str(version)):
        vulns.append({
            "cve_id": advisory.get("id", "ROUTEROS-UNKNOWN"),
            "package_name": "routeros",
            "package_version": str(version),
            "pkg_type": "firmware",
            "host_id": host["id"],
            "scan_id": scan_id,
            "severity": advisory.get("severity", "medium"),
            "cvss_score": advisory.get("cvss_score"),
            "summary": advisory.get("summary", "RouterOS advisory match"),
            "fixed_version": advisory.get("fixed_version", ""),
            "references_json": json.dumps(advisory.get("references", [])),
            "source_path": advisory.get("source", "routeros_feed"),
        })
    return vulns
