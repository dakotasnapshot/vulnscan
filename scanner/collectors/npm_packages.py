"""Collect Node.js (npm) packages from remote hosts."""

import json
import logging
from .ssh import ssh_exec

logger = logging.getLogger("vulnscan.collectors.npm")

# Directories to search for node_modules
SEARCH_DIRS = [
    "/var/www", "/srv", "/opt", "/home", "/root",
    "/usr/local", "/Users"
]


def collect_npm_packages(host: dict) -> list[dict]:
    """Collect installed npm packages from a remote host.

    Searches for package.json files in node_modules directories
    and extracts name + version.
    """
    packages = []
    seen = set()

    # Build search command - find top-level node_modules packages
    dirs_exist_check = " ".join(f'"{d}"' for d in SEARCH_DIRS)
    cmd = f"""
    for base in {dirs_exist_check}; do
        [ -d "$base" ] || continue
        find "$base" -maxdepth 8 -path "*/node_modules/*/package.json" \\
            -not -path "*/node_modules/*/node_modules/*" \\
            2>/dev/null
    done | head -5000
    """

    rc, out, _ = ssh_exec(host, cmd, timeout=180)
    if rc != 0 or not out.strip():
        logger.debug(f"No npm packages found on {host['address']}")
        return []

    pkg_files = out.strip().splitlines()
    logger.info(f"Found {len(pkg_files)} npm package.json files on {host['address']}")

    # Batch read: extract name and version from each package.json
    # Do it in chunks to avoid command line length limits
    chunk_size = 100
    for i in range(0, len(pkg_files), chunk_size):
        chunk = pkg_files[i:i + chunk_size]
        # Build a jq command to extract name+version
        files_arg = " ".join(f'"{f}"' for f in chunk)
        read_cmd = f"""
        for f in {files_arg}; do
            if [ -f "$f" ]; then
                name=$(python3 -c "import json,sys; d=json.load(open('$f')); print(d.get('name',''))" 2>/dev/null || echo "")
                ver=$(python3 -c "import json,sys; d=json.load(open('$f')); print(d.get('version',''))" 2>/dev/null || echo "")
                if [ -n "$name" ] && [ -n "$ver" ]; then
                    echo "$name\\t$ver\\t$f"
                fi
            fi
        done
        """

        # Simpler approach: use grep
        read_cmd = f"""
        for f in {files_arg}; do
            [ -f "$f" ] || continue
            name=$(grep -m1 '"name"' "$f" 2>/dev/null | sed 's/.*"name"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/')
            ver=$(grep -m1 '"version"' "$f" 2>/dev/null | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/')
            [ -n "$name" ] && [ -n "$ver" ] && echo "$name\\t$ver\\t$f"
        done
        """

        rc2, out2, _ = ssh_exec(host, read_cmd, timeout=120)
        if rc2 != 0 or not out2.strip():
            continue

        for line in out2.strip().splitlines():
            parts = line.split("\t")
            if len(parts) >= 3:
                name, version, path = parts[0], parts[1], parts[2]
                key = f"{name}@{version}:{path}"
                if key not in seen:
                    seen.add(key)
                    # Determine the project root (two dirs up from package.json in node_modules)
                    source = _extract_project_path(path)
                    packages.append({
                        "name": name,
                        "version": version,
                        "pkg_type": "npm",
                        "ecosystem": "npm",
                        "source_path": source,
                    })

    logger.info(f"Collected {len(packages)} unique npm packages from {host['address']}")
    return packages


def _extract_project_path(pkg_json_path: str) -> str:
    """Extract the project root from a node_modules package.json path.

    /var/www/myapp/node_modules/axios/package.json -> /var/www/myapp
    """
    parts = pkg_json_path.split("/node_modules/")
    if len(parts) >= 2:
        return parts[0]
    return pkg_json_path
