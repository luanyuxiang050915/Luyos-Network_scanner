#!/usr/bin/env python3
"""
配置常量模块 - 全网段端口扫描器

包含所有全局常量定义: 端口映射、漏洞端口、OS指纹、Web指纹、爆破/漏洞注册表等
"""
import os
from typing import List, Dict, Tuple

# ============================================================================
# 路径配置
# ============================================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "reports")
DICT_PATH = os.path.join(SCRIPT_DIR, "password_dict.txt")

# ============================================================================
# 端口服务映射
# ============================================================================

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

# 高风险/漏洞端口 - 风险提示 (仅有字典匹配, 未做协议级确认)
# 格式: "风险提示: [描述]"
# 有专门检测函数的端口会在 exploits.py 中进一步确认
VULNERABLE_PORTS: Dict[int, str] = {
    21: "FTP - 匿名登录/弱口令风险",
    22: "SSH - 弱口令/暴力破解风险",
    23: "Telnet - 明文传输/弱口令风险",
    25: "SMTP - 邮件伪造/开放中继",
    53: "DNS - DNS放大攻击/区域传输",
    80: "HTTP - Web漏洞(注入/XSS/RCE等)",
    110: "POP3 - 明文传输/弱口令",
    111: "RPC - NFS挂载/RPC漏洞",
    135: "MS-RPC - 与永恒之蓝相关/远程利用",
    137: "NetBIOS - 信息泄露",
    139: "NetBIOS - 文件共享/弱口令",
    143: "IMAP - 明文传输/弱口令",
    161: "SNMP - 默认团体字/public访问",
    389: "LDAP - 信息泄露/弱口令",
    443: "HTTPS - Web漏洞(Heartbleed等)",
    445: "SMB - 待检测: 永恒之蓝(MS17-010) / SMBv1",
    873: "Rsync - 未授权访问",
    1099: "RMI-Registry - 反序列化漏洞",
    1433: "MSSQL - 弱口令/命令执行",
    1521: "Oracle-DB - 弱口令/TNS投毒",
    2049: "NFS - 未授权挂载",
    2375: "Docker-REST - 待检测: 未授权API访问",
    2376: "Docker-REST-TLS - 未授权API访问",
    3128: "Squid-Proxy - 开放代理",
    3306: "MySQL - 弱口令/提权",
    3389: "RDP - 待检测: BlueKeep(CVE-2019-0708) / 弱口令",
    3690: "SVN - 信息泄露",
    4444: "Metasploit - 后门监听端口",
    4786: "Cisco-Smart-Install - 待检测: 远程利用(CVE-2018-0171)",
    4848: "GlassFish - 弱口令/反序列化",
    5000: "Docker-Registry - 未授权访问",
    5432: "PostgreSQL - 弱口令/提权",
    5555: "Android-ADB - 未授权调试",
    5601: "Kibana - 未授权访问",
    5672: "RabbitMQ - 弱口令",
    5900: "VNC - 弱口令",
    5984: "CouchDB - 未授权访问",
    5985: "WinRM - 弱口令/远程执行",
    6379: "Redis - 待检测: 未授权访问/写公钥",
    6443: "K8s-API - 未授权访问",
    7001: "WebLogic - 反序列化/弱口令",
    7474: "Neo4j - 未授权访问",
    8000: "HTTP-Alt - Web漏洞",
    8009: "AJP - Ghostcat(CVE-2020-1938)",
    8080: "HTTP-Proxy - Web漏洞/未授权代理",
    8088: "Hadoop-YARN - 待检测: 未授权RCE",
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

# 有专门协议级检测函数的端口 (在 exploits.py 中实现)
# 这些端口的漏洞会被 detect 函数进一步确认, 从"待确认"变为"已确认"
DETECTABLE_VULN_PORTS = {445, 3389, 6379, 2375, 8088, 4786}

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

# 弱口令爆破服务映射
BRUTE_SERVICE_MAP: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
}

# 默认用户名字典
DEFAULT_USERNAMES: Dict[str, List[str]] = {
    "FTP": ["anonymous", "ftp", "admin", "root", "user", "test"],
    "SSH": ["root", "admin", "administrator", "ubuntu", "centos", "debian", "kali", "test", "user", "oracle"],
    "Telnet": ["root", "admin", "administrator", "guest", "user", "test"],
    "MySQL": ["root", "admin", "mysql", "test"],
    "MSSQL": ["sa", "admin", "administrator", "sql"],
    "RDP": ["administrator", "admin", "user", "guest"],
    "PostgreSQL": ["postgres", "admin", "root", "test"],
}

# Paramiko 可用性标志
try:
    import paramiko as _paramiko
    _HAS_PARAMIKO = True
except ImportError:
    _HAS_PARAMIKO = False
