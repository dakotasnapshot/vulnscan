"""Collect OS-level packages (dpkg, rpm, apk, brew)."""

import logging
from .ssh import ssh_exec

logger = logging.getLogger("vulnscan.collectors.os")


def collect_os_packages(host: dict) -> list[dict]:
    """Collect installed OS packages from a remote host."""
    os_family = host.get("os_family", "")
    os_name = host.get("os_name", "").lower()
    packages = []

    if os_family == "linux":
        # Try dpkg (Debian/Ubuntu)
        packages = _collect_dpkg(host)
        if not packages:
            # Try rpm (RHEL/CentOS/Fedora)
            packages = _collect_rpm(host)
        if not packages:
            # Try apk (Alpine)
            packages = _collect_apk(host)
    elif os_family == "darwin":
        packages = _collect_brew(host)

    logger.info(f"Collected {len(packages)} OS packages from {host['address']}")
    return packages


def _collect_dpkg(host: dict) -> list[dict]:
    """Collect packages from dpkg (Debian/Ubuntu)."""
    cmd = "dpkg-query -W -f='${Package}\\t${Version}\\t${Status}\\n' 2>/dev/null | grep 'install ok installed'"
    rc, out, _ = ssh_exec(host, cmd, timeout=60)
    if rc != 0 or not out.strip():
        return []

    packages = []
    for line in out.strip().splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            packages.append({
                "name": parts[0],
                "version": parts[1],
                "pkg_type": "os",
                "ecosystem": _detect_debian_ecosystem(host),
                "source_path": "dpkg",
            })
    return packages


def _detect_debian_ecosystem(host: dict) -> str:
    """Detect specific Debian ecosystem (Debian, Ubuntu)."""
    os_name = host.get("os_name", "").lower()
    if "ubuntu" in os_name:
        return "Ubuntu"
    elif "debian" in os_name:
        return "Debian"
    return "Debian"


def _collect_rpm(host: dict) -> list[dict]:
    """Collect packages from rpm (RHEL/CentOS/Fedora)."""
    cmd = "rpm -qa --queryformat '%{NAME}\\t%{VERSION}-%{RELEASE}\\n' 2>/dev/null"
    rc, out, _ = ssh_exec(host, cmd, timeout=60)
    if rc != 0 or not out.strip():
        return []

    packages = []
    for line in out.strip().splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            packages.append({
                "name": parts[0],
                "version": parts[1],
                "pkg_type": "os",
                "ecosystem": "Red Hat",
                "source_path": "rpm",
            })
    return packages


def _collect_apk(host: dict) -> list[dict]:
    """Collect packages from apk (Alpine)."""
    cmd = "apk list --installed 2>/dev/null"
    rc, out, _ = ssh_exec(host, cmd, timeout=60)
    if rc != 0 or not out.strip():
        return []

    packages = []
    for line in out.strip().splitlines():
        # Format: name-version-rrelease arch {origin} (license) [installed]
        if " [installed]" not in line:
            continue
        parts = line.split(" ")[0]  # name-version-rrelease
        # Split name from version at last hyphen before a digit
        idx = _find_version_split(parts)
        if idx > 0:
            packages.append({
                "name": parts[:idx],
                "version": parts[idx+1:],
                "pkg_type": "os",
                "ecosystem": "Alpine",
                "source_path": "apk",
            })
    return packages


def _find_version_split(s: str) -> int:
    """Find the split point between package name and version in Alpine format."""
    for i in range(len(s) - 1, 0, -1):
        if s[i] == '-' and i + 1 < len(s) and s[i + 1].isdigit():
            # Walk back to find the actual name-version boundary
            return i
    return -1


def _collect_brew(host: dict) -> list[dict]:
    """Collect packages from Homebrew (macOS)."""
    cmd = "brew list --versions 2>/dev/null"
    rc, out, _ = ssh_exec(host, cmd, timeout=60)
    if rc != 0 or not out.strip():
        return []

    packages = []
    for line in out.strip().splitlines():
        parts = line.split()
        if len(parts) >= 2:
            packages.append({
                "name": parts[0],
                "version": parts[-1],  # Last version listed is current
                "pkg_type": "os",
                "ecosystem": "Homebrew",
                "source_path": "brew",
            })
    return packages
