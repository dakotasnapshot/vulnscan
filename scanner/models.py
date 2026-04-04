"""Data models for VulnScan."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class PackageType(str, Enum):
    OS = "os"           # dpkg, rpm, brew
    NPM = "npm"         # Node.js packages
    PIP = "pip"         # Python packages
    GEM = "gem"         # Ruby gems
    GO = "go"           # Go modules
    CARGO = "cargo"     # Rust crates
    DOCKER = "docker"   # Docker image layers


@dataclass
class Host:
    id: Optional[int] = None
    name: str = ""
    address: str = ""
    ssh_user: str = "root"
    ssh_password: Optional[str] = None
    ssh_key_path: Optional[str] = None
    ssh_port: int = 22
    os_family: str = ""       # linux, darwin, windows
    os_name: str = ""         # Ubuntu 24.04, macOS 15.3, etc.
    enabled: bool = True
    last_scan: Optional[str] = None
    created_at: Optional[str] = None
    tags: list[str] = field(default_factory=list)

    def to_dict(self):
        d = vars(self).copy()
        d["tags"] = ",".join(self.tags) if self.tags else ""
        return d

    @classmethod
    def from_row(cls, row: dict):
        h = cls(**{k: v for k, v in row.items() if k in cls.__dataclass_fields__})
        if isinstance(h.tags, str):
            h.tags = [t.strip() for t in h.tags.split(",") if t.strip()]
        return h


@dataclass
class Package:
    name: str
    version: str
    pkg_type: PackageType
    host_id: int
    ecosystem: str = ""      # e.g., "npm", "PyPI", "Debian", "Alpine"
    source_path: str = ""    # where it was found (e.g., /var/www/app/node_modules)
    scan_id: Optional[int] = None


@dataclass
class Vulnerability:
    id: Optional[int] = None
    cve_id: str = ""
    package_name: str = ""
    package_version: str = ""
    pkg_type: str = ""
    host_id: int = 0
    scan_id: int = 0
    severity: Severity = Severity.UNKNOWN
    cvss_score: Optional[float] = None
    summary: str = ""
    fixed_version: str = ""
    references: str = ""
    source_path: str = ""
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    status: str = "open"     # open, acknowledged, fixed, false_positive


@dataclass
class ScanResult:
    host_id: int
    scan_id: int
    started_at: str
    finished_at: Optional[str] = None
    packages_found: int = 0
    vulns_found: int = 0
    status: str = "running"  # running, completed, failed
    error: Optional[str] = None
