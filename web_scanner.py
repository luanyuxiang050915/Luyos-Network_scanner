#!/usr/bin/env python3
"""
Web 应用扫描模块 - 集成到全网段端口扫描器

功能:
  1. Web 目录/文件路径爆破
  2. CMS 指纹识别 (WordPress/Joomla/Drupal/Tomcat等)
  3. WAF 识别 (Cloudflare/ModSecurity/AWS/Incapsula等)
  4. SQL 注入检测 (错误回显)
  5. XSS 检测 (反射型)

依赖: 仅使用 Python 标准库
"""
import socket
import ssl
import urllib.parse
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional, Set, Any

# ============================================================================
# 常量定义
# ============================================================================

# 常见Web目录/文件路径字典
WEB_PATH_DICT = [
    # ---- 通用文件 ----
    "/", "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/.git/HEAD", "/.svn/entries", "/.env", "/.DS_Store",
    "/README.md", "/CHANGELOG.md", "/LICENSE.txt",
    # ---- 管理后台 ----
    "/admin/", "/administrator/", "/wp-admin/", "/wp-login.php",
    "/manager/", "/console/", "/dashboard/", "/cpanel/",
    "/phpmyadmin/", "/phpMyAdmin/", "/mysql/", "/db/",
    "/adminer.php", "/admin.php", "/login/", "/user/login",
    "/api/", "/api/v1/", "/api/v2/", "/graphql",
    # ---- 配置/备份 ----
    "/backup/", "/bak/", "/backups/",
    "/config/", "/conf/", "/config.php", "/wp-config.php",
    "/wp-config.bak", "/config.yml",
    "/web.config", "/web.xml", "/application.properties",
    "/WEB-INF/web.xml", "/WEB-INF/",
    # ---- 上传/文件 ----
    "/upload/", "/uploads/", "/files/", "/download/",
    "/images/", "/img/", "/css/", "/js/", "/static/",
    # ---- 开发/调试 ----
    "/test/", "/debug/", "/dev/", "/staging/",
    "/phpinfo.php", "/info.php", "/test.php",
    "/server-status", "/server-info",
    "/actuator/", "/actuator/health", "/actuator/env",
    "/swagger-ui.html", "/swagger/", "/api-docs",
    "/springboot-actuator/",
    # ---- 版本控制 ----
    "/.git/config", "/.gitignore", "/.svn/wc.db",
    # ---- 日志 ----
    "/logs/", "/log/", "/error.log", "/access.log",
    # ---- CMS 特征 ----
    "/wp-content/", "/wp-includes/", "/wp-json/wp/v2/users",
    "/administrator/manifests/files/joomla.xml",
    "/sites/default/settings.php",
    "/misc/drupal.js",
    "/typo3/",
    # ---- 常见框架 ----
    "/vendor/", "/composer.json", "/package.json",
    "/Dockerfile", "/Jenkinsfile",
    # ---- 其他敏感 ----
    "/.htaccess", "/favicon.ico",
    "/cgi-bin/", "/webdav/",
    "/jmx-console/", "/web-console/",
    "/solr/admin/", "/_all_dbs", "/_utils/",
    "/sap/bc/gui/sap/its/webgui/",
    "/owa/auth/logon.aspx",
    "/ecp/", "/autodiscover/",
]

# CMS 指纹特征库
CMS_SIGNATURES: Dict[str, dict] = {
    "WordPress": {
        "paths": ["/wp-content/", "/wp-includes/", "/wp-admin/"],
        "headers": {"X-Powered-By": None},
        "body_patterns": [
            r'<meta name="generator" content="WordPress',
            r'/wp-login\.php\?',
            r'wp-json/wp/v2/',
            r'wp-content/themes/',
            r'wp-content/plugins/',
        ],
        "version_patterns": [
            r'WordPress\s+([\d.]+)',
            r'<meta name="generator" content="WordPress\s+([\d.]+)',
        ],
    },
    "Joomla": {
        "paths": ["/administrator/", "/components/", "/modules/"],
        "body_patterns": [
            r'Joomla!',
            r'<meta name="generator" content="Joomla!',
        ],
        "version_patterns": [
            r'Joomla!\s*([\d.]+)',
        ],
    },
    "Drupal": {
        "paths": ["/sites/default/", "/misc/drupal.js"],
        "body_patterns": [
            r'Drupal\.settings',
            r'<meta name="Generator" content="Drupal',
        ],
        "version_patterns": [
            r'Drupal\s+([\d.]+)',
        ],
    },
    "Apache Tomcat": {
        "paths": ["/docs/", "/examples/", "/manager/html"],
        "headers": {"Server": "Apache-Coyote"},
        "body_patterns": [
            r'Apache Tomcat',
        ],
        "version_patterns": [
            r'Apache Tomcat/([\d.]+)',
        ],
    },
    "phpMyAdmin": {
        "paths": ["/phpmyadmin/", "/phpMyAdmin/"],
        "body_patterns": [
            r'phpMyAdmin',
        ],
        "version_patterns": [
            r'phpMyAdmin\s+([\d.]+)',
            r'pma_version\s*=\s*["\']([\d.]+)',
        ],
    },
    "Nginx": {
        "headers": {"Server": None},
        "body_patterns": [
            r'nginx',
            r'<hr><center>nginx',
        ],
        "version_patterns": [
            r'nginx/([\d.]+)',
        ],
    },
    "IIS": {
        "headers": {"Server": None},
        "body_patterns": [
            r'IIS Windows Server',
            r'<title>IIS',
        ],
        "version_patterns": [
            r'Microsoft-IIS/([\d.]+)',
        ],
    },
    "Apache": {
        "headers": {"Server": None},
        "version_patterns": [
            r'Apache/([\d.]+)',
        ],
    },
}

# WAF 检测签名库
WAF_SIGNATURES: Dict[str, dict] = {
    "Cloudflare": {
        "headers": ["CF-Ray", "CF-Cache-Status", "cf-chl-bypass"],
        "cookie_patterns": [r'__cfduid', r'cf_clearance'],
        "response_patterns": [
            r'Cloudflare Ray ID:',
        ],
    },
    "ModSecurity": {
        "response_patterns": [
            r'ModSecurity',
            r'This error was generated by Mod_Security',
            r'mod_security',
        ],
    },
    "AWS WAF": {
        "headers": ["X-Amzn-RequestId", "x-amz-id-2"],
        "cookie_patterns": [r'aws-waf-token'],
    },
    "Incapsula / Imperva": {
        "headers": ["X-CDN", "X-Iinfo"],
        "cookie_patterns": [r'incap_ses_', r'visid_incap_'],
        "response_patterns": [r'Incapsula.*blocked'],
    },
    "Sucuri": {
        "headers": ["X-Sucuri-ID", "X-Sucuri-Cache"],
        "cookie_patterns": [r'sucuri_cloudproxy_'],
        "response_patterns": [r'Sucuri'],
    },
    "F5 BIG-IP ASM": {
        "cookie_patterns": [r'TS[a-f0-9]{6,}', r'BIGipServer'],
        "response_patterns": [r'The requested URL was rejected'],
    },
    "FortiWeb": {
        "cookie_patterns": [r'FORTIWAFSID'],
    },
    "Barracuda WAF": {
        "cookie_patterns": [r'barra_counter_session'],
        "response_patterns": [r'Barracuda'],
    },
    "Akamai": {
        "headers": ["X-Akamai-Transformed"],
    },
    "阿里云WAF": {
        "cookie_patterns": [r'aliyungf_tc'],
        "response_patterns": [r'阿里云WAF'],
    },
    "知道创宇": {
        "cookie_patterns": [r'yunsuo_session'],
        "response_patterns": [r'yunsuo'],
    },
}

# SQL 注入测试载荷
SQLI_TEST_PAYLOADS = [
    ("'", "单引号错误"),
    ('"', "双引号错误"),
    ("' OR '1'='1", "OR恒真"),
    ("' OR 1=1-- ", "OR注释"),
    ("1 AND 1=1", "AND恒真"),
    ("1' AND '1'='2", "AND恒假"),
    ("1' UNION SELECT NULL-- ", "UNION注入"),
    ("1' ORDER BY 1-- ", "ORDER探测"),
]

# SQL 错误特征模式
SQLI_ERROR_PATTERNS = [
    r'SQL syntax.*MySQL',           r'Warning.*mysql_',
    r'MySQLSyntaxErrorException',   r'valid MySQL result',
    r'PostgreSQL.*ERROR',           r'Warning.*\Wpg_',
    r'ORA-\d{5}',                   r'Oracle.*Driver',
    r'SQLite.*Exception',           r'SQLite\.JDBCDriver',
    r'SQL Server.*Driver',          r'\[SQL Server\]',
    r'Microsoft OLE DB.*SQL Server',r'JDBC.*SQLServer',
    r'Unclosed quotation mark',     r'ODBC.*Driver',
    r'com\.mysql\.jdbc',            r'org\.postgresql',
    r'org\.sqlite',                 r'net\.sourceforge\.jtds',
    r'com\.microsoft\.sqlserver',
]

# XSS 测试载荷
XSS_TEST_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '\'"><svg/onload=alert(1)>',
]

# ============================================================================
# 数据结构
# ============================================================================

class WebScanTarget:
    """Web 扫描目标"""

    def __init__(self, host: str, port: int, scheme: str = "http"):
        self.host = host
        self.port = port
        self.scheme = scheme
        self.base_url = f"{scheme}://{host}:{port}"

    def __repr__(self):
        return f"WebScanTarget({self.base_url})"


class DirScanResult:
    """目录爆破单项结果"""

    def __init__(self, path: str, status: int, size: int = 0, redirect: str = ""):
        self.path = path
        self.status = status
        self.size = size
        self.redirect = redirect

    def to_dict(self) -> dict:
        d = {"path": self.path, "status": self.status, "size": self.size}
        if self.redirect:
            d["redirect"] = self.redirect
        return d


class CMSResult:
    """CMS 识别结果"""

    def __init__(self):
        self.cms: str = ""
        self.version: str = ""
        self.confidence: str = "low"

    def to_dict(self) -> dict:
        return {
            "cms": self.cms,
            "version": self.version,
            "confidence": self.confidence,
        }


class WAFResult:
    """WAF 识别结果"""

    def __init__(self):
        self.waf: str = ""
        self.evidence: str = ""
        self.confidence: str = "low"

    def to_dict(self) -> dict:
        return {
            "waf": self.waf,
            "evidence": self.evidence,
            "confidence": self.confidence,
        }


class VulnResult:
    """Web 漏洞检测结果"""

    def __init__(self, vuln_type: str, url: str, payload: str, evidence: str = ""):
        self.vuln_type = vuln_type
        self.url = url
        self.payload = payload
        self.evidence = evidence

    def to_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type,
            "url": self.url,
            "payload": self.payload,
            "evidence": self.evidence,
        }


class WebScanResult:
    """单个目标的 Web 扫描综合结果"""

    def __init__(self, target: WebScanTarget):
        self.target = target
        self.server_header: str = ""
        self.title: str = ""
        self.status_code: int = 0
        self.content_type: str = ""
        self.cms: CMSResult = CMSResult()
        self.waf: WAFResult = WAFResult()
        self.discovered_dirs: List[DirScanResult] = []
        self.vulnerabilities: List[VulnResult] = []
        self.scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "target": self.target.base_url,
            "host": self.target.host,
            "port": self.target.port,
            "scheme": self.target.scheme,
            "server": self.server_header,
            "title": self.title,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "cms": self.cms.to_dict(),
            "waf": self.waf.to_dict(),
            "discovered_dirs": [d.to_dict() for d in self.discovered_dirs],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "scan_time_sec": round(self.scan_time, 2),
        }


# ============================================================================
# HTTP 工具函数
# ============================================================================

def _http_raw_request(
    host: str,
    port: int,
    path: str = "/",
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[bytes] = None,
    timeout: float = 5.0,
    use_ssl: bool = False,
    max_size: int = 524288,
) -> Tuple[int, Dict[str, str], bytes]:
    """发送原始 HTTP 请求, 返回 (状态码, 响应头字典, 响应体字节)

    Args:
        max_size: 响应体最大接收字节数, 默认 512KB
    """
    if headers is None:
        headers = {}

    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                      " (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Connection": "close",
    }

    for k, v in default_headers.items():
        if k not in headers:
            headers[k] = v

    request_line = f"{method} {path} HTTP/1.0\r\n"
    header_lines = ""
    for k, v in headers.items():
        header_lines += f"{k}: {v}\r\n"
    header_lines += f"Host: {host}\r\n"

    full_request = (request_line + header_lines + "\r\n").encode()
    if body:
        full_request = (request_line + header_lines +
                        f"Content-Length: {len(body)}\r\n\r\n").encode() + body

    sock = None
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw_sock = socket.create_connection((host, port), timeout=timeout)
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = socket.create_connection((host, port), timeout=timeout)

        sock.settimeout(timeout)
        sock.sendall(full_request)

        response_data = b""
        while True:
            try:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                response_data += chunk
                if len(response_data) >= max_size:
                    break
                # 检查是否已经收到完整响应体
                if b"\r\n\r\n" in response_data:
                    header_end = response_data.find(b"\r\n\r\n")
                    headers_part = response_data[:header_end]
                    # 简单检查 Content-Length
                    cl_match = re.search(rb'Content-Length:\s*(\d+)',
                                         headers_part, re.I)
                    if cl_match:
                        content_length = int(cl_match.group(1))
                        body_start = header_end + 4
                        if len(response_data) - body_start >= content_length:
                            break
            except socket.timeout:
                break

    except Exception:
        return 0, {}, b""
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    if not response_data:
        return 0, {}, b""

    # 解析响应
    header_end = response_data.find(b"\r\n\r\n")
    if header_end == -1:
        return 0, {}, response_data

    header_part = response_data[:header_end].decode("utf-8", errors="replace")
    body_part = response_data[header_end + 4:]

    # 解析状态行
    status_code = 0
    response_headers: Dict[str, str] = {}
    lines = header_part.split("\r\n")
    for i, line in enumerate(lines):
        if i == 0:
            parts = line.split(" ", 2)
            if len(parts) >= 2 and parts[1].isdigit():
                status_code = int(parts[1])
        else:
            if ":" in line:
                key, _, val = line.partition(":")
                response_headers[key.strip()] = val.strip()

    return status_code, response_headers, body_part


def _http_get(
    host: str, port: int, path: str = "/",
    timeout: float = 5.0, use_ssl: bool = False,
) -> Tuple[int, Dict[str, str], bytes]:
    """GET 请求快捷方法"""
    return _http_raw_request(host, port, path, "GET", timeout=timeout, use_ssl=use_ssl)


# ============================================================================
# 网站基本信息获取
# ============================================================================

def fetch_site_info(target: WebScanTarget, timeout: float = 5.0) -> Dict[str, Any]:
    """获取网站基本信息: 状态码、Server头、Title、Content-Type"""
    use_ssl = (target.scheme == "https")
    status, headers, body = _http_get(
        target.host, target.port, "/", timeout=timeout, use_ssl=use_ssl
    )

    info = {
        "status_code": status,
        "server": headers.get("Server", headers.get("server", "")),
        "content_type": headers.get("Content-Type", headers.get("content-type", "")),
        "title": "",
        "body_sample": "",
    }

    if body:
        body_str = body.decode("utf-8", errors="replace")
        title_match = re.search(r'<title[^>]*>(.*?)</title>',
                                body_str, re.I | re.S)
        if title_match:
            info["title"] = title_match.group(1).strip()
        info["body_sample"] = body_str[:2000]

    return info


# ============================================================================
# CMS 指纹识别
# ============================================================================

def identify_cms(target: WebScanTarget, info: Dict[str, Any],
                 timeout: float = 5.0) -> CMSResult:
    """识别 CMS 类型与版本"""
    result = CMSResult()
    use_ssl = (target.scheme == "https")
    body_text = info.get("body_sample", "")
    server_header = info.get("server", "")

    for cms_name, sig in CMS_SIGNATURES.items():
        score = 0
        version = ""
        body_matched = False

        # 1. 路径检测 (需要同时有 body 匹配才计入, 避免误报)
        path_hits = 0
        for path in sig.get("paths", []):
            try:
                s, _, _ = _http_get(target.host, target.port, path,
                                    timeout=timeout, use_ssl=use_ssl)
                if s and s < 500:
                    path_hits += 1
            except Exception:
                pass

        # 2. Header 检测
        for header_key in sig.get("headers", {}):
            header_lower = header_key.lower()
            for resp_key in info:
                if resp_key.lower() == header_lower:
                    val = str(info.get(resp_key, ""))
                    expected = sig["headers"][header_key]
                    if expected is None or expected.lower() in val.lower():
                        score += 2

        # 3. body 模式匹配
        for pattern in sig.get("body_patterns", []):
            if re.search(pattern, body_text, re.I):
                score += 2
                body_matched = True
                break  # 一个 body 匹配就足够

        # 路径匹配只有在 body 也匹配时才有效加分
        if body_matched:
            score += path_hits

        # 4. 版本提取
        for vp in sig.get("version_patterns", []):
            vm = re.search(vp, body_text, re.I)
            if vm:
                version = vm.group(1)
                score += 1
                break
        if not version:
            for vp in sig.get("version_patterns", []):
                vm = re.search(vp, server_header, re.I)
                if vm:
                    version = vm.group(1)
                    score += 1
                    break

        if score >= 1 and body_matched:
            if not result.cms or score > (2 if result.confidence == "low" else 4):
                result.cms = cms_name
                result.version = version
                if score >= 4:
                    result.confidence = "high"
                elif score >= 2:
                    result.confidence = "medium"
                else:
                    result.confidence = "low"

    return result


# ============================================================================
# WAF 识别
# ============================================================================

def identify_waf_by_request(target: WebScanTarget,
                             base_info: Dict[str, Any],
                             timeout: float = 5.0) -> WAFResult:
    """通过发送测试请求和检查响应特征识别 WAF"""
    result = WAFResult()
    use_ssl = (target.scheme == "https")
    best_score = 0

    # 发送一个触发WAF的测试请求
    test_payload = "/?id=1' OR '1'='1"
    try:
        status, headers, body = _http_raw_request(
            target.host, target.port, test_payload,
            timeout=timeout, use_ssl=use_ssl
        )
    except Exception:
        status, headers, body = 0, {}, b""

    body_text = body.decode("utf-8", errors="replace") if body else ""
    all_headers_lower = {k.lower(): v for k, v in headers.items()}

    for waf_name, sig in WAF_SIGNATURES.items():
        score = 0
        evidence_parts = []

        # 1. 响应头匹配
        for h_name in sig.get("headers", []):
            for hk, hv in headers.items():
                if hk.lower() == h_name.lower():
                    score += 3
                    evidence_parts.append(f"Header: {hk}={hv[:80]}")

        # 2. Cookie 匹配
        for hk, hv in headers.items():
            if hk.lower() == "set-cookie":
                hv_lower = hv.lower()
                for cp in sig.get("cookie_patterns", []):
                    if re.search(cp, hv_lower):
                        score += 3
                        evidence_parts.append(f"Cookie: {hv[:80]}")

        # 3. 响应体匹配
        for rp in sig.get("response_patterns", []):
            if re.search(rp, body_text, re.I) or re.search(
                rp, base_info.get("body_sample", ""), re.I
            ):
                score += 2
                evidence_parts.append(f"Body: {rp[:60]}")

        if score > best_score:
            best_score = score
            result.waf = waf_name
            result.evidence = " | ".join(evidence_parts[:3])
            if score >= 5:
                result.confidence = "high"
            elif score >= 3:
                result.confidence = "medium"
            else:
                result.confidence = "low"

    # 也检查原始响应
    if not result.waf:
        base_body = base_info.get("body_sample", "")
        for waf_name, sig in WAF_SIGNATURES.items():
            score = 0
            evidence_parts = []
            for rp in sig.get("response_patterns", []):
                if re.search(rp, base_body, re.I):
                    score += 1
                    evidence_parts.append(f"Body: {rp[:60]}")
            if score > best_score:
                best_score = score
                result.waf = waf_name
                result.evidence = " | ".join(evidence_parts)
                result.confidence = "low" if score < 2 else "medium"

    return result


# ============================================================================
# 目录爆破
# ============================================================================

def _scan_single_path(
    host: str, port: int, path: str,
    use_ssl: bool = False, timeout: float = 3.0
) -> Optional[DirScanResult]:
    """扫描单个路径, 返回 DirScanResult 或 None"""
    try:
        status, headers, body = _http_get(
            host, port, path, timeout=timeout, use_ssl=use_ssl
        )

        if status == 0:
            return None

        # 跳过 404 (真正的404通常返回小页面)
        if status == 404 and len(body) < 2000:
            return None
        if status in (400, 401, 403, 405, 500, 502, 503):
            return None
        # 301/302 重定向也记录下来
        if status in (301, 302, 307, 308):
            location = headers.get("Location", headers.get("location", ""))
            return DirScanResult(path, status, len(body), redirect=location)

        if 200 <= status < 400:
            return DirScanResult(path, status, len(body))

        return None
    except Exception:
        return None


def directory_bruteforce(
    target: WebScanTarget,
    path_dict: Optional[List[str]] = None,
    threads: int = 50,
    timeout: float = 3.0,
) -> List[DirScanResult]:
    """多线程目录爆破

    Args:
        target: Web 扫描目标
        path_dict: 自定义路径字典, 为 None 时使用内置字典
        threads: 并发线程数
        timeout: 单个请求超时秒数
    """
    if path_dict is None:
        path_dict = WEB_PATH_DICT

    use_ssl = (target.scheme == "https")
    results: List[DirScanResult] = []
    progress_lock = threading.Lock()
    completed = 0
    total = len(path_dict)

    print(f"\n  [*] 目录爆破: {target.base_url} ({total} 条路径, {threads} 线程)")

    tasks = [(target.host, target.port, p, use_ssl, timeout) for p in path_dict]

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(_scan_single_path, host, port, path, ssl_flag, timeout): path
            for host, port, path, ssl_flag, timeout in tasks
        }

        for future in as_completed(futures):
            path = futures[future]
            with progress_lock:
                completed += 1
            try:
                r = future.result()
                if r:
                    results.append(r)
                    with progress_lock:
                        print(f"    [{r.status:>3}] {target.base_url}{r.path}", flush=True)
            except Exception:
                pass

            with progress_lock:
                if completed % 50 == 0 or completed == total:
                    print(f"    ... 进度: {completed}/{total} "
                          f"({completed * 100 // total}%), "
                          f"已发现: {len(results)}", flush=True)

    print(f"  [+] 目录爆破完成: 发现 {len(results)} 个有效路径")
    return results


# ============================================================================
# SQL 注入检测
# ============================================================================

def _test_sqli_single(
    host: str, port: int, path: str,
    param: str, method: str, payload: str, label: str,
    use_ssl: bool = False, timeout: float = 5.0,
) -> Optional[VulnResult]:
    """对单个参数进行 SQL 注入测试"""

    def normalize_body(b: bytes) -> str:
        return b.decode("utf-8", errors="replace").replace("\r", "").replace("\n", "")

    try:
        # 正常请求
        normal_status, _, normal_body = _http_get(
            host, port, path, timeout=timeout, use_ssl=use_ssl
        )
        if not normal_body:
            return None

        normal_text = normalize_body(normal_body)
        normal_len = len(normal_text)

        # 带 payload 的请求
        if method == "GET":
            test_params = urllib.parse.urlencode({param: payload})
            test_path = path + ("&" if "?" in path else "?") + test_params
            test_status, _, test_body = _http_get(
                host, port, test_path, timeout=timeout, use_ssl=use_ssl
            )
        else:
            test_body_data = urllib.parse.urlencode({param: payload}).encode()
            test_status, _, test_body = _http_raw_request(
                host, port, path, method="POST", body=test_body_data,
                timeout=timeout, use_ssl=use_ssl,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

        if not test_body:
            return None

        test_text = normalize_body(test_body)
        test_len = len(test_text)

        # 1. 检查响应差异
        if test_status != normal_status:
            return VulnResult(
                "SQL注入",
                f"{host}:{port}{path}?{param}={urllib.parse.quote(payload)}",
                payload,
                f"状态码差异: {normal_status} -> {test_status}"
            )

        # 2. 检查 SQL 错误特征
        for pattern in SQLI_ERROR_PATTERNS:
            if re.search(pattern, test_text, re.I) and not re.search(pattern, normal_text, re.I):
                return VulnResult(
                    "SQL注入",
                    f"{host}:{port}{path}?{param}={urllib.parse.quote(payload)}",
                    payload,
                    f"SQL错误: {pattern}"
                )

    except Exception:
        pass

    return None


def sql_injection_scan(
    target: WebScanTarget,
    timeout: float = 5.0,
) -> List[VulnResult]:
    """对目标进行基础 SQL 注入检测

    策略: 对首页 URL 参数和表单进行简单测试
    """
    results: List[VulnResult] = []
    use_ssl = (target.scheme == "https")

    print(f"\n  [*] SQL注入检测: {target.base_url}")

    # 获取首页找出可能的参数点
    _, _, body = _http_get(target.host, target.port, "/",
                           timeout=timeout, use_ssl=use_ssl)
    if not body:
        return results

    body_text = body.decode("utf-8", errors="replace")

    # 提取可能的 URL 参数目标
    # 1. 从 <a href> 中提取带参数的链接
    param_candidates: Set[str] = set()
    link_matches = re.findall(r'href=["\']([^"\']*\?[^"\']+)["\']', body_text, re.I)
    for link in link_matches[:10]:
        if "?" in link:
            try:
                parsed = urllib.parse.urlparse(link)
                for pname in urllib.parse.parse_qs(parsed.query).keys():
                    param_candidates.add(pname)
            except Exception:
                pass

    # 2. 从 <form> 中提取 input 参数
    form_inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', body_text, re.I)
    for pname in form_inputs[:10]:
        param_candidates.add(pname)

    # 3. 如果没有找到, 使用常见参数名
    if not param_candidates:
        param_candidates = {"id", "page", "search", "q", "cat", "user"}

    total_tests = len(param_candidates) * len(SQLI_TEST_PAYLOADS)
    tested = 0

    for param in list(param_candidates)[:5]:
        for payload, label in SQLI_TEST_PAYLOADS:
            tested += 1
            r = _test_sqli_single(
                target.host, target.port, "/", param,
                "GET", payload, label, use_ssl, timeout
            )
            if r:
                results.append(r)
                print(f"    [!!!] {r.vuln_type}: {r.evidence}", flush=True)

    if tested > 0:
        print(f"  [+] SQL注入检测完成: 测试 {tested} 次, 发现 {len(results)} 处可疑")

    return results


# ============================================================================
# XSS 检测
# ============================================================================

def xss_scan(
    target: WebScanTarget,
    timeout: float = 5.0,
) -> List[VulnResult]:
    """对目标进行基础反射型 XSS 检测"""
    results: List[VulnResult] = []
    use_ssl = (target.scheme == "https")

    print(f"\n  [*] XSS检测: {target.base_url}")

    # 提取可能的反射点
    _, _, body = _http_get(target.host, target.port, "/",
                           timeout=timeout, use_ssl=use_ssl)
    if not body:
        return results

    body_text = body.decode("utf-8", errors="replace")

    # 从 URL 参数提取反射点
    param_candidates: Set[str] = set()
    link_matches = re.findall(r'href=["\']([^"\']*\?[^"\']+)["\']', body_text, re.I)
    for link in link_matches[:5]:
        try:
            parsed = urllib.parse.urlparse(link)
            for pname in urllib.parse.parse_qs(parsed.query).keys():
                param_candidates.add(pname)
        except Exception:
            pass

    if not param_candidates:
        param_candidates = {"q", "search", "s", "query", "keyword"}

    total_tests = len(param_candidates) * len(XSS_TEST_PAYLOADS)
    tested = 0

    for param in list(param_candidates)[:3]:
        for payload in XSS_TEST_PAYLOADS:
            tested += 1
            try:
                test_params = urllib.parse.urlencode({param: payload})
                test_path = "/" + ("&" if "?" in "/" else "?") + test_params
                status, _, test_body = _http_get(
                    target.host, target.port, test_path,
                    timeout=timeout, use_ssl=use_ssl
                )
                if test_body:
                    test_text = test_body.decode("utf-8", errors="replace")
                    # 检查 payload 是否被原样反射
                    if payload in test_text:
                        results.append(VulnResult(
                            "XSS(反射型)",
                            f"{target.base_url}{test_path}",
                            payload,
                            "payload被反射到页面中"
                        ))
                        print(f"    [!!!] XSS: {param}={payload}", flush=True)
            except Exception:
                pass

    if tested > 0:
        print(f"  [+] XSS检测完成: 测试 {tested} 次, 发现 {len(results)} 处可疑")

    return results


# ============================================================================
# 综合 Web 扫描 (入口函数)
# ============================================================================

def scan_web_target(
    target: WebScanTarget,
    path_dict: Optional[List[str]] = None,
    dir_threads: int = 50,
    timeout: float = 5.0,
    skip_dir: bool = False,
    skip_sqli: bool = False,
    skip_xss: bool = False,
) -> WebScanResult:
    """对单个 Web 目标执行完整扫描

    Args:
        target: Web 扫描目标
        path_dict: 自定义目录字典
        dir_threads: 目录爆破线程数
        timeout: 请求超时
        skip_dir: 跳过目录爆破
        skip_sqli: 跳过SQL注入检测
        skip_xss: 跳过XSS检测
    """
    result = WebScanResult(target)
    start_time = time.time()

    print(f"\n{'='*60}")
    print(f"[*] Web 扫描: {target.base_url}")
    print(f"{'='*60}")

    # 1. 基本信息
    info = fetch_site_info(target, timeout)
    result.status_code = info["status_code"]
    result.server_header = info["server"]
    result.title = info["title"]
    result.content_type = info["content_type"]

    print(f"    状态码: {result.status_code}")
    if result.server_header:
        print(f"    Server: {result.server_header}")
    if result.title:
        print(f"    Title: {result.title[:80]}")

    # 2. CMS 指纹
    result.cms = identify_cms(target, info, timeout)
    if result.cms.cms:
        ver_str = f" {result.cms.version}" if result.cms.version else ""
        print(f"    CMS: {result.cms.cms}{ver_str} "
              f"(置信度: {result.cms.confidence})")

    # 3. WAF 识别
    result.waf = identify_waf_by_request(target, info, timeout)
    if result.waf.waf:
        print(f"    WAF: {result.waf.waf} "
              f"(置信度: {result.waf.confidence})")

    # 4. 目录爆破
    if not skip_dir:
        result.discovered_dirs = directory_bruteforce(
            target, path_dict, threads=dir_threads, timeout=timeout
        )

    # 5. SQL 注入检测
    if not skip_sqli and result.status_code in (200, 301, 302):
        result.vulnerabilities.extend(
            sql_injection_scan(target, timeout)
        )

    # 6. XSS 检测
    if not skip_xss and result.status_code in (200, 301, 302):
        result.vulnerabilities.extend(
            xss_scan(target, timeout)
        )

    result.scan_time = time.time() - start_time
    print(f"\n  [+] {target.base_url} 扫描完成, 耗时 {result.scan_time:.1f}s")

    return result


def scan_web_hosts(
    hosts,  # List[HostInfo] from main.py
    path_dict: Optional[List[str]] = None,
    dir_threads: int = 50,
    timeout: float = 5.0,
    skip_dir: bool = False,
    skip_sqli: bool = False,
    skip_xss: bool = False,
    only_http: bool = True,
) -> Dict[str, WebScanResult]:
    """扫描所有主机上的 Web 服务

    Args:
        hosts: 主机信息列表 (HostInfo from main.py)
        path_dict: 自定义目录字典
        dir_threads: 目录爆破线程数
        timeout: 请求超时
        skip_dir: 跳过目录爆破
        skip_sqli: 跳过SQL注入检测
        skip_xss: 跳过XSS检测
        only_http: 仅扫描 HTTP/HTTPS 端口 (不用 TLS 检测其他端口)

    Returns:
        { "ip:port": WebScanResult } 字典
    """
    results: Dict[str, WebScanResult] = {}

    # 收集所有 Web 目标
    web_targets: List[WebScanTarget] = []

    for host in hosts:
        if not host.is_alive and not host.open_ports:
            continue
        for port_result in host.open_ports:
            if port_result.state != "open":
                continue
            port = port_result.port
            if port in (80, 8000, 8080, 8888, 9999, 8010, 8081, 8088, 9000):
                web_targets.append(WebScanTarget(host.ip, port, "http"))
            elif port in (443, 8443, 9443, 10443):
                web_targets.append(WebScanTarget(host.ip, port, "https"))

    if not web_targets:
        print("\n[*] 未发现 Web 服务端口, 跳过 Web 扫描")
        return results

    print(f"\n{'='*60}")
    print(f"[*] Web 应用扫描阶段 - 发现 {len(web_targets)} 个 Web 目标")
    print(f"{'='*60}")

    for target in web_targets:
        key = f"{target.host}:{target.port}"
        try:
            results[key] = scan_web_target(
                target, path_dict=path_dict, dir_threads=dir_threads,
                timeout=timeout, skip_dir=skip_dir, skip_sqli=skip_sqli,
                skip_xss=skip_xss,
            )
        except Exception as e:
            print(f"  [!] {target.base_url} 扫描失败: {e}")

    # 总结
    total_dirs = sum(len(r.discovered_dirs) for r in results.values())
    total_vulns = sum(len(r.vulnerabilities) for r in results.values())
    cms_found = sum(1 for r in results.values() if r.cms.cms)
    waf_found = sum(1 for r in results.values() if r.waf.waf)

    print(f"\n{'='*60}")
    print(f"  Web 扫描总结")
    print(f"{'='*60}")
    print(f"  扫描目标: {len(web_targets)} 个")
    print(f"  发现目录: {total_dirs} 个")
    print(f"  CMS识别: {cms_found} 个")
    print(f"  WAF识别: {waf_found} 个")
    print(f"  Web漏洞: {total_vulns} 个")
    print(f"{'='*60}")

    return results


# ============================================================================
# Web 扫描结果导出
# ============================================================================

def export_web_json(web_results: Dict[str, "WebScanResult"], filepath: str):
    """导出 Web 扫描结果为 JSON"""
    report = {
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_targets": len(web_results),
        "total_discovered_dirs": sum(len(r.discovered_dirs) for r in web_results.values()),
        "total_vulnerabilities": sum(len(r.vulnerabilities) for r in web_results.values()),
        "targets": [r.to_dict() for r in web_results.values()],
    }
    import json
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"[+] Web扫描 JSON 报告已保存: {filepath}")


def export_web_csv(web_results: Dict[str, "WebScanResult"], filepath: str):
    """导出 Web 扫描结果为 CSV"""
    lines = [
        "URL,端口,协议,状态码,Server,Title,CMS,CMS版本,WAF,"
        "发现目录数,Web漏洞数,扫描耗时(s)\n"
    ]

    for r in web_results.values():
        t = r.target
        cms = r.cms.cms or ""
        cms_ver = r.cms.version or ""
        waf = r.waf.waf or ""

        lines.append(
            f'"{t.host}",{t.port},{t.scheme},{r.status_code},'
            f'"{r.server_header}",'
            f'"{r.title.replace(chr(34), chr(39)) if r.title else ""}",'
            f'"{cms}","{cms_ver}","{waf}",'
            f'{len(r.discovered_dirs)},{len(r.vulnerabilities)},'
            f'{r.scan_time:.2f}\n'
        )

    with open(filepath, "w", encoding="utf-8-sig") as f:
        f.writelines(lines)
    print(f"[+] Web扫描 CSV 报告已保存: {filepath}")


def export_web_html(web_results: Dict[str, "WebScanResult"], filepath: str):
    """导出 Web 扫描结果为 HTML 可视化报告"""
    items_html = ""
    dirs_html = ""

    for r in web_results.values():
        t = r.target
        cms_str = ""
        if r.cms.cms:
            ver = f" {r.cms.version}" if r.cms.version else ""
            cms_str = (f'<span class="tag tag-cms">{r.cms.cms}{ver}</span> '
                       f'({r.cms.confidence})')

        waf_str = ""
        if r.waf.waf:
            waf_str = (f'<span class="tag tag-waf">{r.waf.waf}</span> '
                       f'({r.waf.confidence})')

        vuln_str = ""
        for v in r.vulnerabilities:
            vuln_str += (f'<span class="tag tag-danger">{v.vuln_type}</span> '
                         f'{v.evidence[:80]}<br>')

        items_html += f"""
        <tr>
            <td><a href="{t.base_url}" target="_blank">{t.base_url}</a></td>
            <td>{r.status_code}</td>
            <td>{r.server_header}</td>
            <td>{r.title[:60] if r.title else "-"}</td>
            <td>{cms_str or "-"}</td>
            <td>{waf_str or "-"}</td>
            <td>{len(r.discovered_dirs)}</td>
            <td>{vuln_str or "-"}</td>
        </tr>"""

        for d in r.discovered_dirs:
            cls = ("danger" if d.status in (200, 301, 302, 307)
                   else "warning" if d.status in (401, 403)
                   else "")
            size_kb = f"{d.size / 1024:.1f}KB" if d.size > 1024 else f"{d.size}B"
            redirect_html = ""
            if d.redirect:
                redirect_html = (f' <span style="color:#888">'
                                 f'→ {d.redirect[:60]}</span>')
            dirs_html += f"""
            <tr class="{cls}">
                <td>{r.target.host}:{r.target.port}</td>
                <td>{d.status}</td>
                <td>{d.path}</td>
                <td>{size_kb}</td>
                <td>{redirect_html}</td>
            </tr>"""

    total_targets = len(web_results)
    total_dirs = sum(len(r.discovered_dirs) for r in web_results.values())
    total_vulns = sum(len(r.vulnerabilities) for r in web_results.values())
    cms_found = sum(1 for r in web_results.values() if r.cms.cms)
    waf_found = sum(1 for r in web_results.values() if r.waf.waf)

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Web 应用扫描报告</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    background: #1a1a2e; color: #e0e0e0; font-family: 'Segoe UI', sans-serif;
    padding: 30px;
}}
h1 {{ color: #e94560; text-align: center; margin-bottom: 5px; }}
.subtitle {{ text-align: center; color: #888; margin-bottom: 30px; font-size: 14px; }}
.stats {{
    display: flex; gap: 20px; justify-content: center; flex-wrap: wrap;
    margin-bottom: 30px;
}}
.stat-card {{
    background: #16213e; border: 1px solid #0f3460; border-radius: 8px;
    padding: 20px 30px; text-align: center; min-width: 140px;
}}
.stat-card .num {{ font-size: 36px; font-weight: bold; color: #e94560; display: block; }}
.stat-card .label {{ color: #aaa; font-size: 13px; margin-top: 5px; }}
h2 {{
    color: #e94560; border-bottom: 2px solid #e94560;
    padding-bottom: 8px; margin: 30px 0 15px;
}}
table {{
    width: 100%; border-collapse: collapse; margin-bottom: 20px;
    font-size: 13px;
}}
th {{
    background: #0f3460; color: #e0e0e0; padding: 12px 10px;
    text-align: left; font-weight: 600;
}}
td {{ padding: 10px; border-bottom: 1px solid #16213e; }}
tr:hover {{ background: #16213e; }}
.tag {{
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 11px; font-weight: bold;
}}
.tag-cms {{ background: #1a5276; color: #85c1e9; }}
.tag-waf {{ background: #7d3c98; color: #d7bde2; }}
.tag-danger {{ background: #922b21; color: #f1948a; }}
.danger {{ border-left: 3px solid #e94560; }}
.warning {{ border-left: 3px solid #f39c12; }}
a {{ color: #85c1e9; text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
.footer {{ text-align: center; color: #555; margin-top: 40px; font-size: 12px; }}
@media print {{ body {{ background: white; color: black; }} }}
</style>
</head>
<body>
<h1>Web 应用扫描报告</h1>
<p class="subtitle">扫描时间: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>

<div class="stats">
    <div class="stat-card"><span class="num">{total_targets}</span><span class="label">Web 目标</span></div>
    <div class="stat-card"><span class="num">{total_dirs}</span><span class="label">发现目录</span></div>
    <div class="stat-card"><span class="num">{cms_found}</span><span class="label">CMS 识别</span></div>
    <div class="stat-card"><span class="num">{waf_found}</span><span class="label">WAF 识别</span></div>
    <div class="stat-card"><span class="num">{total_vulns}</span><span class="label">Web 漏洞</span></div>
</div>

<h2>目标概览</h2>
<table>
<tr><th>URL</th><th>状态码</th><th>Server</th><th>Title</th><th>CMS</th><th>WAF</th><th>目录数</th><th>漏洞</th></tr>
{items_html}
</table>

<h2>发现目录详情</h2>
<table>
<tr><th>主机</th><th>状态码</th><th>路径</th><th>大小</th><th>重定向</th></tr>
{dirs_html}
</table>

<p class="footer">全网段端口扫描器 v3.0 - Web 应用扫描模块</p>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] Web扫描 HTML 报告已保存: {filepath}")


# ============================================================================
# 加载自定义字典
# ============================================================================

def load_web_path_dict(filepath: str) -> List[str]:
    """从文件加载自定义路径字典 (每行一个路径)"""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            paths = [
                line.strip()
                for line in f
                if line.strip() and not line.strip().startswith("#")
            ]
        print(f"[+] 已加载自定义字典: {filepath} ({len(paths)} 条)")
        return paths
    except FileNotFoundError:
        print(f"[!] 字典文件不存在: {filepath}, 使用内置字典")
        return WEB_PATH_DICT
    except Exception as e:
        print(f"[!] 加载字典失败: {e}, 使用内置字典")
        return WEB_PATH_DICT
