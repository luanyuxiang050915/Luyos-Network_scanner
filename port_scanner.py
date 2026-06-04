#!/usr/bin/env python3
"""
端口扫描模块 - TCP/UDP 扫描、Banner 抓取、版本识别、Web 服务识别
"""

import socket
import struct
import time
import threading
import queue
import re
from typing import List, Optional

from config import WEB_SERVER_SIGNATURES
from core import ScanResult, get_service_name, check_vulnerable, HostInfo


def tcp_connect_scan(ip: str, port: int, timeout: float = 2.0) -> Optional[ScanResult]:
    """TCP Connect 端口扫描 + Banner 获取"""
    # 延迟导入漏洞检测函数, 避免与 exploits 模块产生循环引用
    try:
        from exploits import _detect_eternal_blue
    except ImportError:
        from main import _detect_eternal_blue

    try:
        from exploits import _detect_vulns_for_port
    except ImportError:
        from main import _detect_vulns_for_port

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
