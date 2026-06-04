#!/usr/bin/env python3
"""
主机发现模块 - ICMP Ping + TCP Ping 存活探测

从 main.py 中提取的独立模块:
  - icmp_ping: ICMP Ping 探测
  - tcp_ping: TCP Ping 探测
  - discover_alive_hosts: 批量主机存活发现
"""

import socket
import struct
import time
import threading
import platform
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple

from core import HostInfo, resolve_hostname, ip_to_int, guess_os_by_ttl


# ============================================================================
# ICMP Ping 存活探测
# ============================================================================

def icmp_ping(ip: str, timeout: float = 1.0) -> Tuple[bool, int, str]:
    """ICMP Ping 探测主机是否存活 (Windows 兼容)"""
    system = platform.system().lower()

    if system == "windows":
        cmd = f"ping -n 1 -w {int(timeout * 1000)} {ip}"
    else:
        cmd = f"ping -c 1 -W {int(timeout)} {ip}"

    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout + 2
        )
        output = result.stdout + result.stderr
        alive = result.returncode == 0

        ttl = 0
        if alive:
            if system == "windows":
                match = re.search(r"TTL=(\d+)", output, re.IGNORECASE)
            else:
                match = re.search(r"ttl=(\d+)", output, re.IGNORECASE)
            if match:
                ttl = int(match.group(1))

        os_guess = guess_os_by_ttl(ttl) if alive else ""
        return alive, ttl, os_guess
    except Exception:
        return False, 0, ""


def tcp_ping(ip: str, port: int = 80, timeout: float = 1.0) -> bool:
    """TCP Ping 探测主机存活 (适用于禁用 ICMP 的主机)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


# ============================================================================
# 批量主机存活发现
# ============================================================================

def discover_alive_hosts(
    targets: List[str],
    use_icmp: bool = True,
    use_tcp_ping: bool = True,
    ping_timeout: float = 1.0,
    max_workers: int = 200
) -> List[HostInfo]:
    """发现存活主机"""
    print(f"\n{'='*60}")
    print(f"[*] 主机发现阶段 - 共 {len(targets)} 个目标")
    print(f"{'='*60}")

    host_map: Dict[str, HostInfo] = {}

    def probe_host(ip: str) -> HostInfo:
        info = HostInfo(ip)
        alive = False

        if use_icmp:
            is_alive, ttl, os_guess = icmp_ping(ip, ping_timeout)
            if is_alive:
                alive = True
                info.ttl = ttl
                info.os_guess = os_guess

        if not alive and use_tcp_ping:
            for probe_port in [80, 443, 22, 445, 3389, 135, 8080]:
                if tcp_ping(ip, probe_port, ping_timeout):
                    alive = True
                    break

        info.is_alive = alive
        if alive:
            info.hostname = resolve_hostname(ip)

        return info

    completed = 0
    alive_count = 0

    print(f"[*] 使用 {'ICMP' if use_icmp else ''}"
          f"{' + ' if use_icmp and use_tcp_ping else ''}"
          f"{'TCP-Ping' if use_tcp_ping else ''} 探测...\n")

    lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(probe_host, ip): ip for ip in targets}
        for future in as_completed(future_map):
            info = future.result()
            with lock:
                host_map[info.ip] = info
                completed += 1
                if info.is_alive:
                    alive_count += 1
                    status = "[存活]"
                else:
                    status = "[离线]"
                hostname_str = f" ({info.hostname})" if info.hostname else ""
                os_str = f" [{info.os_guess}]" if info.os_guess else ""
                print(f"  {completed:>4}/{len(targets)} {status} {info.ip:<16}"
                      f" TTL={info.ttl:<4}{os_str}{hostname_str}", flush=True)

    print(f"\n[+] 主机发现完成: {alive_count}/{len(targets)} 台主机存活")

    # 打印存活汇总
    if alive_count > 0:
        print(f"\n{'='*60}")
        print(f"  存活主机汇总")
        print(f"{'='*60}")
        print(f"  {'IP 地址':<18} {'主机名':<25} {'TTL':<6} {'操作系统猜测'}")
        print(f"  {'─'*55}")
        for info in sorted(host_map.values(), key=lambda h: ip_to_int(h.ip)):
            if info.is_alive:
                print(f"  {info.ip:<18} {info.hostname[:24]:<25} {info.ttl:<6} {info.os_guess}")
        print(f"{'='*60}")

    return list(host_map.values())
