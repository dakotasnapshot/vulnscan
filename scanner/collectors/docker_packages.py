"""Collect packages from Docker containers on remote hosts."""

import json
import logging
from .ssh import ssh_exec

logger = logging.getLogger("vulnscan.collectors.docker")


def collect_docker_packages(host: dict) -> list[dict]:
    """Collect packages from running Docker containers.

    For each running container, collects OS packages and
    checks for node_modules/pip packages.
    """
    packages = []

    # List running containers
    cmd = 'docker ps --format "{{.ID}}\\t{{.Names}}\\t{{.Image}}" 2>/dev/null'
    rc, out, _ = ssh_exec(host, cmd, timeout=30)
    if rc != 0 or not out.strip():
        logger.debug(f"No Docker containers on {host['address']}")
        return []

    containers = []
    for line in out.strip().splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            containers.append({
                "id": parts[0],
                "name": parts[1],
                "image": parts[2],
            })

    logger.info(f"Found {len(containers)} Docker containers on {host['address']}")

    for container in containers:
        cid = container["id"]
        cname = container["name"]

        # Try dpkg inside container
        cmd = f'docker exec {cid} dpkg-query -W -f=\'${{Package}}\\t${{Version}}\\n\' 2>/dev/null | head -2000'
        rc, out, _ = ssh_exec(host, cmd, timeout=30)
        if rc == 0 and out.strip():
            for line in out.strip().splitlines():
                parts = line.split("\t")
                if len(parts) >= 2:
                    packages.append({
                        "name": parts[0],
                        "version": parts[1],
                        "pkg_type": "docker",
                        "ecosystem": "Debian",
                        "source_path": f"docker:{cname} ({container['image']})",
                    })

        # Try apk inside container
        if not (rc == 0 and out.strip()):
            cmd = f'docker exec {cid} apk list --installed 2>/dev/null | head -2000'
            rc, out, _ = ssh_exec(host, cmd, timeout=30)
            if rc == 0 and out.strip():
                for line in out.strip().splitlines():
                    if "[installed]" not in line:
                        continue
                    token = line.split(" ")[0]
                    # name-version format
                    for i in range(len(token) - 1, 0, -1):
                        if token[i] == '-' and i + 1 < len(token) and token[i + 1].isdigit():
                            packages.append({
                                "name": token[:i],
                                "version": token[i + 1:],
                                "pkg_type": "docker",
                                "ecosystem": "Alpine",
                                "source_path": f"docker:{cname} ({container['image']})",
                            })
                            break

        # Check for npm packages in container
        cmd = f'docker exec {cid} sh -c \'find / -maxdepth 6 -path "*/node_modules/*/package.json" -not -path "*/node_modules/*/node_modules/*" 2>/dev/null | head -500\''
        rc, out, _ = ssh_exec(host, cmd, timeout=30)
        if rc == 0 and out.strip():
            files = out.strip().splitlines()
            for f in files[:200]:
                read_cmd = f"""docker exec {cid} sh -c '
                    name=$(grep -m1 "\\\"name\\\"" "{f}" 2>/dev/null | sed "s/.*\\\"name\\\"[[:space:]]*:[[:space:]]*\\\"\\([^\\\"]*\\)\\\".*/\\1/")
                    ver=$(grep -m1 "\\\"version\\\"" "{f}" 2>/dev/null | sed "s/.*\\\"version\\\"[[:space:]]*:[[:space:]]*\\\"\\([^\\\"]*\\)\\\".*/\\1/")
                    [ -n "$name" ] && [ -n "$ver" ] && echo "$name\\t$ver"
                '"""
                rc2, out2, _ = ssh_exec(host, read_cmd, timeout=10)
                if rc2 == 0 and out2.strip():
                    parts = out2.strip().split("\t")
                    if len(parts) >= 2:
                        packages.append({
                            "name": parts[0],
                            "version": parts[1],
                            "pkg_type": "npm",
                            "ecosystem": "npm",
                            "source_path": f"docker:{cname}:{f.rsplit('/node_modules/', 1)[0]}",
                        })

    logger.info(f"Collected {len(packages)} packages from Docker on {host['address']}")
    return packages
