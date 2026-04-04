"""Collect Python (pip) packages from remote hosts."""

import logging
from .ssh import ssh_exec

logger = logging.getLogger("vulnscan.collectors.pip")


def collect_pip_packages(host: dict) -> list[dict]:
    """Collect installed pip packages from a remote host.

    Checks system pip and common virtualenvs.
    """
    packages = []
    seen = set()

    # System pip
    for pip_cmd in ["pip3", "pip"]:
        cmd = f"{pip_cmd} list --format=freeze 2>/dev/null"
        rc, out, _ = ssh_exec(host, cmd, timeout=60)
        if rc == 0 and out.strip():
            for line in out.strip().splitlines():
                if "==" in line:
                    name, version = line.split("==", 1)
                    key = f"{name}@{version}"
                    if key not in seen:
                        seen.add(key)
                        packages.append({
                            "name": name.strip(),
                            "version": version.strip(),
                            "pkg_type": "pip",
                            "ecosystem": "PyPI",
                            "source_path": f"system ({pip_cmd})",
                        })
            break  # Don't double-count

    # Search for virtualenvs
    venv_cmd = """
    for base in /var/www /srv /opt /home /root; do
        [ -d "$base" ] || continue
        find "$base" -maxdepth 5 -name "pyvenv.cfg" 2>/dev/null
    done | head -50
    """
    rc, out, _ = ssh_exec(host, venv_cmd, timeout=60)
    if rc == 0 and out.strip():
        for venv_cfg in out.strip().splitlines():
            venv_dir = venv_cfg.rsplit("/", 1)[0]
            pip_path = f"{venv_dir}/bin/pip"
            cmd = f"{pip_path} list --format=freeze 2>/dev/null"
            rc2, out2, _ = ssh_exec(host, cmd, timeout=30)
            if rc2 == 0 and out2.strip():
                for line in out2.strip().splitlines():
                    if "==" in line:
                        name, version = line.split("==", 1)
                        key = f"{name}@{version}@{venv_dir}"
                        if key not in seen:
                            seen.add(key)
                            packages.append({
                                "name": name.strip(),
                                "version": version.strip(),
                                "pkg_type": "pip",
                                "ecosystem": "PyPI",
                                "source_path": venv_dir,
                            })

    logger.info(f"Collected {len(packages)} pip packages from {host['address']}")
    return packages
