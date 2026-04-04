"""Network and subnet discovery for VulnScan.

Scans subnets for live hosts, detects OS, and can auto-add discovered hosts.
"""

import ipaddress
import socket
import subprocess
import logging
from typing import Optional
from .ssh import ssh_exec

logger = logging.getLogger("vulnscan.collectors.network_discovery")


def ping_host(ip: str, timeout: int = 2) -> bool:
    """Check if a host responds to ping."""
    try:
        result = subprocess.run(
            ['ping', '-c', '1', '-W', str(timeout), ip],
            capture_output=True,
            timeout=timeout + 1
        )
        return result.returncode == 0
    except Exception:
        return False


def scan_tcp_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a TCP port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def detect_os_via_ssh(ip: str, port: int = 22, credentials: list[dict] = None) -> Optional[dict]:
    """Try to detect OS by connecting via SSH with provided credentials.
    
    Args:
        ip: Target IP
        port: SSH port
        credentials: List of dicts with 'username' and 'password'
    
    Returns dict with os_family, os_name, and successful credentials, or None
    """
    if not credentials:
        credentials = [
            {'username': 'root', 'password': 'MellowYellow'},
        ]
    
    for cred in credentials:
        host_dict = {
            'address': ip,
            'ssh_user': cred['username'],
            'ssh_password': cred.get('password'),
            'ssh_key_path': cred.get('key_path'),
            'ssh_port': port
        }
        
        # Try to run a basic command
        rc, stdout, stderr = ssh_exec(host_dict, "uname -s 2>/dev/null || ver 2>/dev/null", timeout=5)
        if rc == 0 and stdout.strip():
            # Success! Try to get more OS info
            rc2, osinfo, _ = ssh_exec(host_dict, "cat /etc/os-release 2>/dev/null || sw_vers 2>/dev/null", timeout=5)
            
            os_family = 'unknown'
            os_name = stdout.strip()
            
            if 'Linux' in stdout:
                os_family = 'linux'
                if rc2 == 0 and 'PRETTY_NAME' in osinfo:
                    for line in osinfo.splitlines():
                        if line.startswith('PRETTY_NAME='):
                            os_name = line.split('=', 1)[1].strip('"')
                            break
            elif 'Darwin' in stdout:
                os_family = 'darwin'
                if rc2 == 0 and 'ProductName' in osinfo:
                    os_name = 'macOS'
            elif 'Windows' in stdout or 'Microsoft' in stdout:
                os_family = 'windows'
            
            return {
                'os_family': os_family,
                'os_name': os_name,
                'ssh_user': cred['username'],
                'ssh_password': cred.get('password'),
                'ssh_key_path': cred.get('key_path'),
                'ssh_port': port
            }
    
    return None


def detect_os_via_banner(ip: str, port: int = 22, timeout: float = 3.0) -> Optional[str]:
    """Try to detect OS from SSH banner without auth."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        
        banner_lower = banner.lower()
        if 'ubuntu' in banner_lower:
            return 'Ubuntu'
        elif 'debian' in banner_lower:
            return 'Debian'
        elif 'openssh' in banner_lower:
            return 'Linux (OpenSSH)'
        elif 'dropbear' in banner_lower:
            return 'Linux (Dropbear)'
        
        return banner.strip()[:100]
    except Exception:
        return None


def detect_service(ip: str) -> dict:
    """Detect what services are running on a host."""
    services = {}
    
    # Common ports to check
    port_map = {
        22: 'ssh',
        80: 'http',
        443: 'https',
        8006: 'proxmox',
        3389: 'rdp',
        5900: 'vnc'
    }
    
    for port, name in port_map.items():
        if scan_tcp_port(ip, port, timeout=0.5):
            services[name] = port
    
    return services


def scan_subnet(subnet: str, credentials: list[dict] = None, 
                quick: bool = False) -> list[dict]:
    """Scan a subnet for live hosts.
    
    Args:
        subnet: CIDR notation (e.g., '192.168.4.0/24')
        credentials: List of credential dicts to try
        quick: If True, only ping; if False, scan ports and try SSH
    
    Returns list of discovered hosts with details
    """
    try:
        network = ipaddress.IPv4Network(subnet, strict=False)
    except ValueError as e:
        logger.error(f"Invalid subnet: {e}")
        return []
    
    discovered = []
    
    for ip in network.hosts():
        ip_str = str(ip)
        logger.info(f"Scanning {ip_str}...")
        
        # Quick ping check first
        if not ping_host(ip_str, timeout=1):
            continue
        
        logger.info(f"Host {ip_str} is alive")
        
        host_info = {
            'ip': ip_str,
            'hostname': None,
            'os_family': 'unknown',
            'os_name': 'unknown',
            'services': {},
            'ssh_accessible': False
        }
        
        # Try to resolve hostname
        try:
            hostname = socket.gethostbyaddr(ip_str)[0]
            host_info['hostname'] = hostname
        except Exception:
            pass
        
        if quick:
            discovered.append(host_info)
            continue
        
        # Detect services
        host_info['services'] = detect_service(ip_str)
        
        # If SSH is available, try to detect OS
        if 'ssh' in host_info['services']:
            # Try banner first (no auth)
            banner = detect_os_via_banner(ip_str)
            if banner:
                host_info['os_name'] = banner
            
            # Try with credentials if provided
            if credentials:
                os_info = detect_os_via_ssh(ip_str, credentials=credentials)
                if os_info:
                    host_info.update(os_info)
                    host_info['ssh_accessible'] = True
        
        # Check for Proxmox web UI
        if 'proxmox' in host_info['services']:
            host_info['os_name'] = 'Proxmox VE'
            host_info['os_family'] = 'linux'
        
        discovered.append(host_info)
    
    return discovered
