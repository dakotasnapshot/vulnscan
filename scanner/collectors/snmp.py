"""SNMP collector for network devices.

Uses system snmpget/snmpwalk so VulnScan stays dependency-light. This is focused
on enough inventory/fingerprinting to classify network hardware and capture
firmware/version facts for vendor-specific vulnerability matching.
"""

from __future__ import annotations

import re
import subprocess
from typing import Any

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
MIKROTIK_ROUTEROS_VERSION_OID = "1.3.6.1.4.1.14988.1.1.4.4.0"
MIKROTIK_FIRMWARE_VERSION_OID = "1.3.6.1.4.1.14988.1.1.7.7.0"
MIKROTIK_BOARD_NAME_OID = "1.3.6.1.4.1.14988.1.1.7.8.0"

MIKROTIK_ENTERPRISE_PREFIX = "1.3.6.1.4.1.14988"
VERSION_RE = re.compile(r"\b(?:routeros\s*)?v?(\d+(?:\.\d+){1,3})\b", re.IGNORECASE)


def _snmp_cmd(host: dict[str, Any], oid: str, walk: bool = False) -> list[str]:
    cmd = ["snmpwalk" if walk else "snmpget", "-v", host.get("snmp_version", "2c")]
    community = host.get("snmp_community")
    if not community:
        raise ValueError("snmp_community required for SNMP polling")
    cmd += ["-c", community, f"{host['address']}:{host.get('snmp_port', 161)}", oid]
    return cmd


def _run_snmp(host: dict[str, Any], oid: str, walk: bool = False, timeout: int = 8) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            _snmp_cmd(host, oid, walk=walk),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            return False, result.stderr.strip() or result.stdout.strip()
        return True, result.stdout.strip()
    except Exception as e:
        return False, str(e)


def _extract_value(snmp_output: str) -> str:
    if " = " not in snmp_output:
        return snmp_output.strip()
    value = snmp_output.split(" = ", 1)[1]
    if ": " in value:
        value = value.split(": ", 1)[1]
    return value.strip().strip('"')


def fingerprint_vendor(sysdescr: str, sysobjectid: str) -> tuple[str, str, str]:
    text = f"{sysdescr} {sysobjectid}".lower()
    if MIKROTIK_ENTERPRISE_PREFIX in sysobjectid or "mikrotik" in text or "routeros" in text:
        return "MikroTik", "routeros", "network_device"
    if "ubiquiti" in text or "unifi" in text:
        return "Ubiquiti", "network_os", "network_device"
    if "cisco" in text:
        return "Cisco", "network_os", "network_device"
    if "juniper" in text or "junos" in text:
        return "Juniper", "network_os", "network_device"
    return "", "", "network_device"


def extract_version(sysdescr: str, vendor: str = "", platform: str = "") -> str:
    match = VERSION_RE.search(sysdescr or "")
    if match:
        return match.group(1)
    return ""


def collect_snmp_facts(host: dict[str, Any]) -> dict[str, Any]:
    if not host.get("snmp_community"):
        return {"snmp_reachable": False, "error": "snmp_community missing"}

    success_descr, raw_descr = _run_snmp(host, SYS_DESCR)
    success_obj, raw_obj = _run_snmp(host, SYS_OBJECT_ID)
    success_name, raw_name = _run_snmp(host, SYS_NAME)

    if not success_descr and not success_obj:
        return {
            "snmp_reachable": False,
            "error": raw_descr or raw_obj or "SNMP polling failed",
        }

    sysdescr = _extract_value(raw_descr) if success_descr else ""
    sysobjectid = _extract_value(raw_obj) if success_obj else ""
    sysname = _extract_value(raw_name) if success_name else ""

    vendor, platform, device_type = fingerprint_vendor(sysdescr, sysobjectid)
    version = extract_version(sysdescr, vendor=vendor, platform=platform)

    extra = {}
    if vendor == "MikroTik" or platform == "routeros":
        ok_ros_ver, raw_ros_ver = _run_snmp(host, MIKROTIK_ROUTEROS_VERSION_OID)
        ok_fw_ver, raw_fw_ver = _run_snmp(host, MIKROTIK_FIRMWARE_VERSION_OID)
        ok_board, raw_board = _run_snmp(host, MIKROTIK_BOARD_NAME_OID)

        routeros_version = _extract_value(raw_ros_ver) if ok_ros_ver else ""
        firmware_version = _extract_value(raw_fw_ver) if ok_fw_ver else ""
        board_name = _extract_value(raw_board) if ok_board else ""

        if routeros_version:
            version = routeros_version

        extra.update({
            "routeros_version": routeros_version,
            "firmware_version": firmware_version,
            "board_name": board_name,
        })

    return {
        "snmp_reachable": True,
        "snmp_sysdescr": sysdescr,
        "snmp_sysobjectid": sysobjectid,
        "snmp_sysname": sysname,
        "vendor": vendor,
        "platform": platform,
        "device_type": device_type,
        "version": version,
        **extra,
    }
