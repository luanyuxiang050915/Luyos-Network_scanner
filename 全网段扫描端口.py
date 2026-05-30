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
    alive_hosts = [h for h in hosts if h.is_alive]
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
                lines.append(f"    {r.port}/{r.protocol:<4} - {svc}{vuln}{banner_info}{brute_info}")

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
        "hosts": [h.to_dict() for h in hosts if h.is_alive],
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
    header = "IP,主机名,OS猜测,TTL,端口,协议,服务,状态,Banner,版本,高危,漏洞说明,响应时间(ms),爆破成功,爆破用户名,爆破密码\n"
    lines = [header]

    for host in hosts:
        if not host.is_alive:
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
                _csv_quote(""), _csv_quote(""), _csv_quote(""),
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
    alive_hosts = [h for h in hosts if h.is_alive]
    total_open = sum(len(h.open_ports) for h in hosts)
    vuln_count = sum(sum(1 for p in h.open_ports if p.is_vulnerable) for h in hosts)
    brute_ok = sum(sum(1 for p in h.open_ports if p.brute_result and p.brute_result.success) for h in hosts)
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
                    {vuln_badge}{brute_badge}
                    {('<div class="vuln-detail">' + _html_escape(r.vuln_reason) + '</div>') if r.is_vulnerable else ''}
                </td>
            </tr>"""

        # 统计该主机
        host_vuln = sum(1 for p in host.open_ports if p.is_vulnerable)
        host_brute = sum(1 for p in host.open_ports if p.brute_result and p.brute_result.success)

        hosts_html += f"""
        <div class="host-group">
            <div class="host-group-header" onclick="this.nextElementSibling.classList.toggle('collapsed')">
                <span class="host-arrow">▾</span>
                <span class="host-ip">{host.ip}</span>
                <span class="host-hostname">{host.hostname or '—'}</span>
                <span class="host-os">{host.os_guess or 'Unknown OS'}</span>
                <span class="host-stats">
                    TTL={host.ttl} | 端口={len(host.open_ports)} | 高危={host_vuln} | 爆破成功={host_brute}
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

    if not any(h.is_alive for h in hosts):
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

    if not any(h.is_alive for h in hosts):
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
