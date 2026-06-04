#!/usr/bin/env python3
"""
核心模块 - 全网段端口扫描器

包含: 数据结构 (ScanResult / BruteResult / HostInfo) + 公共工具函数
"""
import socket
import struct
import ipaddress
import re
from typing import List, Dict, Tuple, Optional

from config import PORT_SERVICE_MAP, VULNERABLE_PORTS, DETECTABLE_VULN_PORTS

# ============================================================================
# 数据结构
# ============================================================================

class ScanResult:
    """端口扫描结果"""

    def __init__(self, host: str, port: int, protocol: str = "TCP"):
        self.host = host
        self.port = port
        self.protocol = protocol
        self.state: str = "closed"
        self.service: str = ""
        self.banner: str = ""
        self.version: str = ""
        self.is_vulnerable: bool = False
        self.vuln_reason: str = ""
        self.response_time: float = 0.0
        self.ttl: int = 0
        self.os_guess: str = ""
        self.brute_result: Optional["BruteResult"] = None
        self.eternal_blue_vuln: bool = False
        self.eternal_blue_os: str = ""
        self.eternal_blue_version: str = ""
        self.vuln_findings: dict = {}

    def to_dict(self) -> dict:
        d = {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "banner": self.banner.strip(),
            "version": self.version,
            "is_vulnerable": self.is_vulnerable,
            "vuln_reason": self.vuln_reason,
            "response_time_ms": round(self.response_time * 1000, 2),
            "ttl": self.ttl,
            "os_guess": self.os_guess,
            "eternal_blue_vuln": self.eternal_blue_vuln,
            "eternal_blue_os": self.eternal_blue_os,
            "eternal_blue_version": self.eternal_blue_version,
            "vuln_findings": self.vuln_findings,
        }
        if self.brute_result:
            d["brute_force"] = self.brute_result.to_dict()
        return d


class BruteResult:
    """爆破结果"""

    def __init__(self):
        self.success: bool = False
        self.service: str = ""
        self.host: str = ""
        self.port: int = 0
        self.username: str = ""
        self.password: str = ""
        self.tried_count: int = 0
        self.elapsed: float = 0.0

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "service": self.service,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "password": self.password,
            "tried_count": self.tried_count,
            "elapsed_sec": round(self.elapsed, 2),
        }


class HostInfo:
    """主机信息"""

    def __init__(self, ip: str):
        self.ip = ip
        self.hostname: str = ""
        self.is_alive: bool = False
        self.mac_address: str = ""
        self.ttl: int = 0
        self.os_guess: str = ""
        self.open_ports: List[ScanResult] = []
        self.scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "is_alive": self.is_alive,
            "mac_address": self.mac_address,
            "os_guess": self.os_guess,
            "ttl": self.ttl,
            "open_ports_count": len(self.open_ports),
            "open_ports": [r.to_dict() for r in self.open_ports],
            "scan_time_sec": round(self.scan_time, 2),
        }


# ============================================================================
# 工具函数
# ============================================================================

def resolve_hostname(ip: str) -> str:
    """反向 DNS 解析"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return ""


def get_service_name(port: int) -> str:
    """获取端口对应的服务名称"""
    if port in PORT_SERVICE_MAP:
        return PORT_SERVICE_MAP[port]
    try:
        return socket.getservbyport(port, "tcp")
    except (OSError, socket.error):
        return "unknown"


def check_vulnerable(port: int) -> Tuple[bool, str]:
    """检查端口是否为已知风险端口

    两级判定:
    - 有专门协议检测函数的端口 (DETECTABLE_VULN_PORTS):
      标记 is_vulnerable=True, 但 reason 显示"待确认"
      后续 exploit 的 detect 函数成功确认后会更新为"已确认"
    - 无检测函数的端口:
      标记 is_vulnerable=True, reason 显示"风险提示"
    """
    if port in VULNERABLE_PORTS:
        desc = VULNERABLE_PORTS[port]
        if port in DETECTABLE_VULN_PORTS:
            return True, f"[待确认] {desc}"
        else:
            return True, f"[风险提示] {desc}"
    return False, ""


def guess_os_by_ttl(ttl: int) -> str:
    """通过 TTL 值猜测操作系统"""
    if ttl <= 32:
        return "路由器/嵌入式设备"
    elif ttl <= 64:
        return "Linux/Unix/macOS"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Cisco/Solaris/网络设备"
    return "未知"


def is_private_ip(ip: str) -> bool:
    """判断是否为私有 IP"""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def get_local_ip() -> str:
    """获取本机 IP 地址"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def ip_to_int(ip: str) -> int:
    """IP 地址转整数, 域名返回一个极大的值使其排在末尾"""
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except OSError:
        return 10 ** 12


def int_to_ip(num: int) -> str:
    """整数转 IP 地址"""
    return socket.inet_ntoa(struct.pack("!I", num))


def resolve_domain(domain: str) -> List[str]:
    """将域名解析为 IP 地址列表"""
    try:
        _, _, ip_list = socket.gethostbyname_ex(domain)
        return ip_list
    except socket.gaierror:
        return []


def parse_targets(target_str: str) -> List[str]:
    """解析目标地址字符串, 支持:
    - 单个 IP: 192.168.1.1
    - 域名: example.com, www.example.com
    - IP 范围: 192.168.1.1-192.168.1.254
    - CIDR: 192.168.1.0/24
    - 逗号分隔混合: 192.168.1.1,10.0.0.0/24,example.com
    """
    targets: List[str] = []
    for part in target_str.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part and "/" not in part:
            try:
                start, end = part.split("-")
                start_int = ip_to_int(start)
                end_int = ip_to_int(end)
                if start_int >= 10 ** 12 or end_int >= 10 ** 12:
                    print(f"[!] 范围不支持域名: {part}")
                    continue
                for ip_int in range(start_int, end_int + 1):
                    targets.append(int_to_ip(ip_int))
            except Exception:
                print(f"[!] 无效的范围格式: {part}")
        elif "/" in part:
            try:
                network = ipaddress.ip_network(part, strict=False)
                for addr in network.hosts():
                    targets.append(str(addr))
            except ValueError:
                print(f"[!] 无效的 CIDR 格式: {part}")
        else:
            try:
                ipaddress.ip_address(part)
                targets.append(part)
            except ValueError:
                ips = resolve_domain(part)
                if ips:
                    targets.extend(ips)
                else:
                    print(f"[!] 无法解析: {part}")
    return sorted(set(targets), key=ip_to_int)
