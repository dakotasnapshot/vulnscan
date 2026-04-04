"""SSH connection helper for remote host scanning."""

import subprocess
import logging

logger = logging.getLogger("vulnscan.ssh")


def ssh_exec(host: dict, command: str, timeout: int = 120) -> tuple[int, str, str]:
    """Execute a command on a remote host via SSH.

    Returns (returncode, stdout, stderr).
    """
    ssh_args = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        "-o", "BatchMode=yes" if host.get("ssh_key_path") else "PubkeyAuthentication=no",
        "-p", str(host.get("ssh_port", 22)),
    ]

    if host.get("ssh_key_path"):
        ssh_args += ["-i", host["ssh_key_path"]]

    target = f"{host['ssh_user']}@{host['address']}"
    ssh_args.append(target)
    ssh_args.append(command)

    # Use sshpass if password auth
    if host.get("ssh_password") and not host.get("ssh_key_path"):
        ssh_args = ["sshpass", "-p", host["ssh_password"]] + ssh_args

    try:
        result = subprocess.run(
            ssh_args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        logger.error(f"SSH timeout for {host['address']}")
        return -1, "", "SSH command timed out"
    except Exception as e:
        logger.error(f"SSH error for {host['address']}: {e}")
        return -1, "", str(e)


def detect_os(host: dict) -> tuple[str, str]:
    """Detect OS family and name on a remote host.

    Returns (os_family, os_name).
    """
    # Try Linux first
    rc, out, _ = ssh_exec(host, "cat /etc/os-release 2>/dev/null || sw_vers 2>/dev/null || ver 2>/dev/null")
    if rc != 0:
        return "unknown", "unknown"

    if "PRETTY_NAME" in out:
        os_family = "linux"
        for line in out.splitlines():
            if line.startswith("PRETTY_NAME="):
                os_name = line.split("=", 1)[1].strip('"')
                return os_family, os_name
        return os_family, "Linux"

    if "ProductName" in out:
        os_family = "darwin"
        name = ""
        version = ""
        for line in out.splitlines():
            if "ProductName" in line:
                name = line.split(":", 1)[1].strip()
            if "ProductVersion" in line:
                version = line.split(":", 1)[1].strip()
        return os_family, f"{name} {version}".strip()

    if "Microsoft Windows" in out:
        return "windows", out.strip().splitlines()[0]

    return "unknown", out.strip()[:80]
