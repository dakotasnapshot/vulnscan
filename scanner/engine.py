"""Main scanning engine — orchestrates collectors and vulnerability matching."""

import logging
from datetime import datetime, timezone
from typing import Optional

from . import database as db
from .collectors.ssh import detect_os
from .collectors.os_packages import collect_os_packages
from .collectors.npm_packages import collect_npm_packages
from .collectors.pip_packages import collect_pip_packages
from .collectors.docker_packages import collect_docker_packages
from .collectors.snmp import collect_snmp_facts
from .collectors.routeros import (
    infer_routeros_device,
    collect_routeros_packages,
    match_routeros_vulnerabilities,
)
from .osv_client import query_batch

logger = logging.getLogger("vulnscan.engine")


def scan_host(host_id: int) -> dict:
    """Run a full scan on a single host.

    1. Detect OS
    2. Collect packages (OS, npm, pip, docker)
    3. Query OSV for vulnerabilities
    4. Store results

    Returns scan summary dict.
    """
    host = db.get_host(host_id)
    if not host:
        return {"error": f"Host {host_id} not found"}

    logger.info(f"Starting scan of {host['name']} ({host['address']})")
    scan_id = db.create_scan(host_id)

    try:
        if host.get("snmp_community"):
            snmp_facts = collect_snmp_facts(host)
            db.insert_device_facts(host_id, scan_id, snmp_facts, source="snmp")

            host_updates = {
                k: snmp_facts[k]
                for k in ["vendor", "platform", "device_type", "version", "snmp_sysdescr", "snmp_sysobjectid"]
                if snmp_facts.get(k)
            }
            if host_updates:
                db.update_host(host_id, **host_updates)
                host.update(host_updates)

        is_routeros = infer_routeros_device(host)

        # Step 1: Detect OS if not already known
        if not is_routeros and (not host.get("os_family") or host["os_family"] == ""):
            os_family, os_name = detect_os(host)
            db.update_host(host_id, os_family=os_family, os_name=os_name)
            host["os_family"] = os_family
            host["os_name"] = os_name
            logger.info(f"Detected OS: {os_family} / {os_name}")

        # Step 2: Collect packages
        all_packages = []

        if is_routeros:
            host["platform"] = host.get("platform") or "routeros"
            host["vendor"] = host.get("vendor") or "MikroTik"
            host["device_type"] = host.get("device_type") or "network_device"
            os_pkgs = collect_routeros_packages(host)
            npm_pkgs = []
            pip_pkgs = []
            docker_pkgs = []
            all_packages.extend(os_pkgs)
        else:
            os_pkgs = collect_os_packages(host)
            all_packages.extend(os_pkgs)

            npm_pkgs = collect_npm_packages(host)
            all_packages.extend(npm_pkgs)

            pip_pkgs = collect_pip_packages(host)
            all_packages.extend(pip_pkgs)

            docker_pkgs = collect_docker_packages(host)
            all_packages.extend(docker_pkgs)

        logger.info(f"Total packages collected: {len(all_packages)} "
                     f"(OS: {len(os_pkgs)}, npm: {len(npm_pkgs)}, "
                     f"pip: {len(pip_pkgs)}, docker: {len(docker_pkgs)})")

        # Store packages
        for pkg in all_packages:
            pkg["host_id"] = host_id
            pkg["scan_id"] = scan_id
        db.insert_packages(all_packages)

        # Step 3: Query OSV for vulnerabilities
        # Deduplicate by name+version+ecosystem for efficient querying
        unique_pkgs = {}
        for pkg in all_packages:
            key = f"{pkg['name']}@{pkg['version']}@{pkg['ecosystem']}"
            if key not in unique_pkgs:
                unique_pkgs[key] = pkg

        if is_routeros:
            logger.info("Matching RouterOS advisories from local feed...")
            vuln_results = {}
        else:
            logger.info(f"Querying OSV for {len(unique_pkgs)} unique packages...")
            vuln_results = query_batch(list(unique_pkgs.values()))

        # Step 4: Map vulnerabilities back to packages and store
        vuln_records = []
        if is_routeros:
            vuln_records.extend(match_routeros_vulnerabilities(host, scan_id))
        else:
            for pkg in all_packages:
                key = f"{pkg['name']}@{pkg['version']}"
                if key in vuln_results:
                    for vuln in vuln_results[key]:
                        vuln_records.append({
                            "cve_id": vuln["cve_id"],
                            "package_name": pkg["name"],
                            "package_version": pkg["version"],
                            "pkg_type": pkg["pkg_type"],
                            "host_id": host_id,
                            "scan_id": scan_id,
                            "severity": vuln["severity"],
                            "cvss_score": vuln.get("cvss_score"),
                            "summary": vuln.get("summary", ""),
                            "fixed_version": vuln.get("fixed_version", ""),
                            "references_json": vuln.get("references", "[]"),
                            "source_path": pkg.get("source_path", ""),
                        })

        # Deduplicate vulns (same CVE+package on same host)
        seen_vulns = set()
        unique_vulns = []
        for v in vuln_records:
            vkey = f"{v['cve_id']}:{v['package_name']}:{v['host_id']}"
            if vkey not in seen_vulns:
                seen_vulns.add(vkey)
                unique_vulns.append(v)

        db.insert_vulnerabilities(unique_vulns)

        # Finalize scan
        db.finish_scan(scan_id, len(all_packages), len(unique_vulns), "completed")

        summary = {
            "scan_id": scan_id,
            "host_id": host_id,
            "host_name": host["name"],
            "status": "completed",
            "packages_found": len(all_packages),
            "vulns_found": len(unique_vulns),
            "by_severity": {
                "critical": sum(1 for v in unique_vulns if v["severity"] == "critical"),
                "high": sum(1 for v in unique_vulns if v["severity"] == "high"),
                "medium": sum(1 for v in unique_vulns if v["severity"] == "medium"),
                "low": sum(1 for v in unique_vulns if v["severity"] == "low"),
            }
        }
        logger.info(f"Scan completed: {summary}")
        return summary

    except Exception as e:
        logger.error(f"Scan failed for {host['name']}: {e}", exc_info=True)
        db.finish_scan(scan_id, 0, 0, "failed", str(e))
        return {"scan_id": scan_id, "host_id": host_id, "status": "failed", "error": str(e)}


def scan_all(enabled_only: bool = True) -> list[dict]:
    """Scan all hosts. Returns list of scan summaries."""
    hosts = db.list_hosts(enabled_only=enabled_only)
    results = []
    for host in hosts:
        result = scan_host(host["id"])
        results.append(result)
    return results


def check_specific_cve(cve_id: str) -> list[dict]:
    """Check all hosts for a specific CVE.

    Returns list of affected hosts with package details.
    """
    from .osv_client import get_vuln_details

    vuln_data = get_vuln_details(cve_id)
    if not vuln_data:
        return []

    # Extract affected package names and version ranges
    affected_pkgs = []
    for affected in vuln_data.get("affected", []):
        pkg_info = affected.get("package", {})
        affected_pkgs.append({
            "name": pkg_info.get("name", ""),
            "ecosystem": pkg_info.get("ecosystem", ""),
            "ranges": affected.get("ranges", []),
            "versions": affected.get("versions", []),
        })

    # TODO: Check installed packages against affected versions
    # For now, return the vuln data
    return affected_pkgs
