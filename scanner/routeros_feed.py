"""RouterOS advisory feed loader and matcher.

Initial implementation uses a local JSON feed so VulnScan can reason about
RouterOS vulnerabilities without pretending MikroTik devices are Linux package
hosts. This is intentionally simple and deterministic.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

FEED_PATH = Path(__file__).resolve().parent.parent / "data" / "routeros_advisories.json"


def _version_tuple(version: str) -> tuple[int, ...]:
    parts = []
    for token in str(version).replace('-', '.').split('.'):
        digits = ''.join(ch for ch in token if ch.isdigit())
        if digits:
            parts.append(int(digits))
        else:
            parts.append(0)
    return tuple(parts)


def version_compare(a: str, b: str) -> int:
    va = _version_tuple(a)
    vb = _version_tuple(b)
    max_len = max(len(va), len(vb))
    va += (0,) * (max_len - len(va))
    vb += (0,) * (max_len - len(vb))
    if va < vb:
        return -1
    if va > vb:
        return 1
    return 0


def version_in_range(version: str, affected_range: dict[str, Any]) -> bool:
    if not version:
        return False
    introduced = affected_range.get("introduced")
    fixed = affected_range.get("fixed")
    last_affected = affected_range.get("last_affected")

    if introduced and version_compare(version, introduced) < 0:
        return False
    if fixed and version_compare(version, fixed) >= 0:
        return False
    if last_affected and version_compare(version, last_affected) > 0:
        return False
    return True


def load_feed() -> list[dict[str, Any]]:
    if not FEED_PATH.exists():
        return []
    return json.loads(FEED_PATH.read_text())


def match_routeros_version(version: str) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for advisory in load_feed():
        for affected in advisory.get("affected", []):
            if version_in_range(version, affected):
                matches.append(advisory)
                break
    return matches
