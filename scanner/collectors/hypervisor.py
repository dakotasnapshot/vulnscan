"""Hypervisor discovery collector for Proxmox and VMware ESXi.

Detects hypervisor type and enumerates VMs/containers.
"""

import logging
import re
from typing import Optional
from .ssh import ssh_exec

logger = logging.getLogger("vulnscan.collectors.hypervisor")


def detect_hypervisor(host: dict) -> str:
    """Detect if host is a hypervisor and which type.
    
    Returns: 'proxmox', 'esxi', or 'none'
    """
    # Check for Proxmox
    rc, stdout, _ = ssh_exec(host, "which pvesh 2>/dev/null || which pct 2>/dev/null || which qm 2>/dev/null")
    if rc == 0 and stdout.strip():
        return 'proxmox'
    
    # Check for VMware ESXi
    rc, stdout, _ = ssh_exec(host, "which vim-cmd 2>/dev/null || which esxcli 2>/dev/null")
    if rc == 0 and stdout.strip():
        return 'esxi'
    
    return 'none'


def discover_proxmox_guests(host: dict) -> list[dict]:
    """Enumerate Proxmox LXC containers and VMs.
    
    Returns list of dicts with: type, vmid, name, status, ip
    """
    guests = []
    
    # Get LXC containers
    rc, stdout, stderr = ssh_exec(host, "pct list 2>/dev/null")
    if rc == 0 and stdout:
        for line in stdout.splitlines()[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 3:
                vmid = parts[0]
                status = parts[1]
                name = parts[2]
                
                # Try to get IP address
                ip = None
                if status.lower() == 'running':
                    rc_ip, ip_out, _ = ssh_exec(host, f"pct exec {vmid} -- hostname -I 2>/dev/null | awk '{{print $1}}'")
                    if rc_ip == 0 and ip_out.strip():
                        ip = ip_out.strip()
                
                guests.append({
                    'type': 'lxc',
                    'vmid': vmid,
                    'name': name,
                    'status': status,
                    'ip': ip,
                    'hypervisor': host['address']
                })
    
    # Get VMs
    rc, stdout, stderr = ssh_exec(host, "qm list 2>/dev/null")
    if rc == 0 and stdout:
        for line in stdout.splitlines()[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 3:
                vmid = parts[0]
                name = parts[1]
                status = parts[2] if len(parts) > 2 else 'unknown'
                
                # Try to get IP via qemu agent
                ip = None
                if status.lower() == 'running':
                    rc_ip, ip_out, _ = ssh_exec(host, f"qm guest cmd {vmid} network-get-interfaces 2>/dev/null | grep -oP '\"ip-address\":\"[0-9.]+' | head -1 | cut -d'\"' -f4")
                    if rc_ip == 0 and ip_out.strip():
                        ip = ip_out.strip()
                
                guests.append({
                    'type': 'qemu',
                    'vmid': vmid,
                    'name': name,
                    'status': status,
                    'ip': ip,
                    'hypervisor': host['address']
                })
    
    return guests


def discover_esxi_guests(host: dict) -> list[dict]:
    """Enumerate VMware ESXi VMs.
    
    Returns list of dicts with: type, vmid, name, status, ip
    """
    guests = []
    
    # Get all VMs
    rc, stdout, stderr = ssh_exec(host, "vim-cmd vmsvc/getallvms 2>/dev/null")
    if rc != 0 or not stdout:
        return guests
    
    for line in stdout.splitlines()[1:]:  # Skip header
        parts = line.split()
        if len(parts) < 2:
            continue
        
        vmid = parts[0]
        name = parts[1]
        
        # Get power state
        status = 'unknown'
        rc_state, state_out, _ = ssh_exec(host, f"vim-cmd vmsvc/power.getstate {vmid} 2>/dev/null")
        if rc_state == 0:
            if 'Powered on' in state_out:
                status = 'running'
            elif 'Powered off' in state_out:
                status = 'stopped'
        
        # Try to get IP address
        ip = None
        if status == 'running':
            rc_ip, ip_out, _ = ssh_exec(host, f"vim-cmd vmsvc/get.guest {vmid} 2>/dev/null | grep -oP 'ipAddress = \"[0-9.]+' | head -1 | cut -d'\"' -f2")
            if rc_ip == 0 and ip_out.strip():
                ip = ip_out.strip()
        
        guests.append({
            'type': 'vmware-vm',
            'vmid': vmid,
            'name': name,
            'status': status,
            'ip': ip,
            'hypervisor': host['address']
        })
    
    return guests


def discover_all_guests(host: dict) -> dict:
    """Discover all guests on a hypervisor host.
    
    Returns dict with hypervisor_type and guests list.
    """
    hv_type = detect_hypervisor(host)
    
    if hv_type == 'proxmox':
        guests = discover_proxmox_guests(host)
    elif hv_type == 'esxi':
        guests = discover_esxi_guests(host)
    else:
        guests = []
    
    return {
        'hypervisor_type': hv_type,
        'hypervisor_host': host['address'],
        'guests': guests
    }
