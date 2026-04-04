"""OSV.dev API client for vulnerability lookups.

Uses the OSV (Open Source Vulnerabilities) database:
https://osv.dev/docs/

Free, no API key required. Supports batch queries.
"""

import json
import logging
import re
import urllib.request
import urllib.error
from time import sleep
from typing import Optional

logger = logging.getLogger("vulnscan.osv")

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"

# Map our ecosystems to OSV ecosystems
ECOSYSTEM_MAP = {
    "npm": "npm",
    "PyPI": "PyPI",
    "Debian": "Debian",
    "Ubuntu": "Ubuntu",
    "Alpine": "Alpine",
    "Red Hat": "Red Hat",
    "Homebrew": None,  # Not in OSV
    "Go": "Go",
    "crates.io": "crates.io",
    "RubyGems": "RubyGems",
}

# CVSS severity thresholds
def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def _parse_cvss_v3_score(vector: str) -> Optional[float]:
    """Extract approximate CVSS v3 base score from a vector string.

    This is a simplified calculation — good enough for severity bucketing.
    """
    # Try to find a score directly if embedded
    # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> ~9.8
    if not vector or not vector.startswith("CVSS:3"):
        return None

    parts = {}
    for segment in vector.split("/"):
        if ":" in segment:
            k, v = segment.split(":", 1)
            parts[k] = v

    # Simplified scoring based on key metrics
    av_scores = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    ac_scores = {"L": 0.77, "H": 0.44}
    pr_scores_u = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_scores_c = {"N": 0.85, "L": 0.68, "H": 0.50}
    ui_scores = {"N": 0.85, "R": 0.62}
    cia_scores = {"H": 0.56, "L": 0.22, "N": 0.0}

    scope_changed = parts.get("S", "U") == "C"
    pr_map = pr_scores_c if scope_changed else pr_scores_u

    av = av_scores.get(parts.get("AV", "N"), 0.85)
    ac = ac_scores.get(parts.get("AC", "L"), 0.77)
    pr = pr_map.get(parts.get("PR", "N"), 0.85)
    ui = ui_scores.get(parts.get("UI", "N"), 0.85)
    c = cia_scores.get(parts.get("C", "N"), 0.0)
    i = cia_scores.get(parts.get("I", "N"), 0.0)
    a = cia_scores.get(parts.get("A", "N"), 0.0)

    # ISS (Impact Sub-Score)
    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if iss <= 0:
        return 0.0

    # Exploitability
    exploit = 8.22 * av * ac * pr * ui

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    if scope_changed:
        score = min(1.08 * (impact + exploit), 10.0)
    else:
        score = min(impact + exploit, 10.0)

    return round(score, 1)


def _extract_severity(vuln_data: dict) -> tuple[str, Optional[float]]:
    """Extract severity and CVSS score from OSV vulnerability data."""
    cvss_score = None
    severity_str = None

    # Method 1: Parse CVSS vector from severity array
    severity_list = vuln_data.get("severity", [])
    for s in severity_list:
        if s.get("type") == "CVSS_V3":
            score = _parse_cvss_v3_score(s.get("score", ""))
            if score is not None:
                cvss_score = score
                severity_str = _cvss_to_severity(score)

    if severity_str and severity_str != "unknown":
        return severity_str, cvss_score

    # Method 2: Check database_specific
    db_specific = vuln_data.get("database_specific", {})

    # Some DBs embed severity directly
    sev = db_specific.get("severity", "")
    if isinstance(sev, str):
        sev_lower = sev.lower()
        if sev_lower in ("critical", "high", "medium", "low"):
            return sev_lower, cvss_score

    # NVD-style scoring
    for key in ("cvss_score", "severity_score", "cvss3_score"):
        val = db_specific.get(key)
        if val and isinstance(val, (int, float)):
            cvss_score = float(val)
            return _cvss_to_severity(cvss_score), cvss_score

    # Method 3: Check ecosystem_specific
    eco_specific = vuln_data.get("ecosystem_specific", {})
    sev = eco_specific.get("severity", "")
    if isinstance(sev, str) and sev.lower() in ("critical", "high", "medium", "low"):
        return sev.lower(), cvss_score

    # Method 4: Infer from CVE ID prefix patterns
    # Debian advisories often lack severity data — try the summary
    summary = vuln_data.get("summary", "") or vuln_data.get("details", "") or ""
    summary_lower = summary.lower()
    if any(w in summary_lower for w in ["remote code execution", "arbitrary code", "buffer overflow", "rce"]):
        return "critical", None
    if any(w in summary_lower for w in ["denial of service", "crash", "dos"]):
        return "medium", None

    return "unknown", cvss_score


def _extract_fixed_version(affected: list) -> str:
    """Extract fixed version from OSV affected data."""
    for a in affected:
        ranges = a.get("ranges", [])
        for r in ranges:
            events = r.get("events", [])
            for event in events:
                if "fixed" in event:
                    return event["fixed"]
    return ""


def _extract_summary(vuln_data: dict) -> str:
    """Extract a useful summary from vulnerability data."""
    summary = vuln_data.get("summary", "")
    if not summary:
        details = vuln_data.get("details", "")
        if details:
            # First sentence or first 300 chars
            first_sentence = details.split(". ")[0]
            summary = first_sentence[:300]
    return summary[:500]


def _fetch_vuln_detail(vuln_id: str) -> Optional[dict]:
    """Fetch full vulnerability details from OSV."""
    try:
        url = f"{OSV_VULN_URL}/{vuln_id}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 429:
            sleep(5)
            return None
        return None
    except Exception:
        return None


def query_batch(packages: list[dict], batch_size: int = 1000) -> dict:
    """Query OSV for vulnerabilities in a batch of packages.

    Step 1: Batch query to find which packages have vulns (returns vuln IDs only).
    Step 2: Fetch full details for each unique vuln ID to get severity/CVSS.

    Args:
        packages: List of dicts with keys: name, version, ecosystem
        batch_size: Max queries per API call

    Returns:
        Dict mapping "name@version" to list of vulnerability dicts
    """
    # Step 1: Batch query to discover vuln IDs per package
    pkg_vuln_ids = {}  # key -> list of vuln IDs
    all_vuln_ids = set()

    for i in range(0, len(packages), batch_size):
        chunk = packages[i:i + batch_size]
        queries = []
        query_map = []

        for pkg in chunk:
            osv_ecosystem = ECOSYSTEM_MAP.get(pkg["ecosystem"])
            if not osv_ecosystem:
                continue
            queries.append({
                "package": {
                    "name": pkg["name"],
                    "ecosystem": osv_ecosystem,
                },
                "version": pkg["version"],
            })
            query_map.append(pkg)

        if not queries:
            continue

        payload = json.dumps({"queries": queries}).encode()

        try:
            req = urllib.request.Request(
                OSV_BATCH_URL,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 429:
                logger.warning("OSV rate limited, waiting 30s...")
                sleep(30)
                continue
            logger.error(f"OSV API error: {e.code} {e.reason}")
            continue
        except Exception as e:
            logger.error(f"OSV API request failed: {e}")
            continue

        batch_results = data.get("results", [])
        for j, result in enumerate(batch_results):
            vulns = result.get("vulns", [])
            if vulns and j < len(query_map):
                pkg = query_map[j]
                key = f"{pkg['name']}@{pkg['version']}"
                vuln_ids = [v.get("id", "") for v in vulns if v.get("id")]
                pkg_vuln_ids[key] = vuln_ids
                all_vuln_ids.update(vuln_ids)

        if i + batch_size < len(packages):
            sleep(1)

    logger.info(f"Found {len(all_vuln_ids)} unique vulnerability IDs across {len(pkg_vuln_ids)} affected packages")

    # Step 2: Fetch full details for each unique vuln ID
    vuln_cache = {}  # vuln_id -> parsed vuln dict
    fetched = 0
    for vuln_id in all_vuln_ids:
        detail = _fetch_vuln_detail(vuln_id)
        fetched += 1
        if detail:
            severity, cvss = _extract_severity(detail)
            summary = _extract_summary(detail)
            vuln_cache[vuln_id] = {
                "cve_id": vuln_id,
                "summary": summary,
                "severity": severity,
                "cvss_score": cvss,
                "fixed_version": _extract_fixed_version(detail.get("affected", [])),
                "references": json.dumps(
                    [r.get("url", "") for r in detail.get("references", [])[:5]]
                ),
            }
        else:
            vuln_cache[vuln_id] = {
                "cve_id": vuln_id,
                "summary": "",
                "severity": "unknown",
                "cvss_score": None,
                "fixed_version": "",
                "references": "[]",
            }

        # Rate limit: ~10 requests per second
        if fetched % 10 == 0:
            sleep(1)
            if fetched % 100 == 0:
                logger.info(f"Fetched {fetched}/{len(all_vuln_ids)} vuln details...")

    # Step 3: Map back to packages
    results = {}
    for key, vuln_ids in pkg_vuln_ids.items():
        results[key] = [vuln_cache[vid] for vid in vuln_ids if vid in vuln_cache]

    return results


def get_vuln_details(vuln_id: str) -> Optional[dict]:
    """Get full details for a specific vulnerability."""
    try:
        url = f"{OSV_VULN_URL}/{vuln_id}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except Exception as e:
        logger.error(f"Failed to fetch vuln {vuln_id}: {e}")
        return None
