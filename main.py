#!/usr/bin/env python3
"""
全网段端口扫描器 v3.0 - 模块化版本

功能特性:
  1. ICMP Ping 存活主机探测
  2. 多线程 TCP/UDP 端口扫描
  3. 服务/版本识别 (Banner Grabbing)
  4. 操作系统指纹识别
  5. Web 应用扫描 (目录爆破/CMS/WAF/SQL注入/XSS)
  6. 弱口令爆破 (SSH/MySQL/MSSQL)
  7. 漏洞检测与利用 (EternalBlue/BlueKeep/Redis/Docker/Hadoop/Cisco)
  8. 后渗透交互式 Shell
  9. 报告导出 (JSON/CSV/HTML)

项目结构:
  config.py          - 全局常量定义
  core.py            - 数据结构 + 公共工具函数
  host_discovery.py  - 存活探测
  port_scanner.py    - 端口扫描 + Banner + 扫描引擎
  exploits.py        - 漏洞检测与利用
  brute_force.py     - 弱口令爆破
  post_exploitation.py - 后渗透 Shell
  reports.py         - 报告生成
  web_scanner.py     - Web 应用扫描
  main.py            - 入口调度 (本文件)
"""
import sys
import os
import time
import argparse
from datetime import datetime

# ── 内部模块导入 ──────────────────────────────────────────
from config import (
    COMMON_PORTS, OUTPUT_DIR, SCRIPT_DIR,
)
from core import (
    HostInfo, parse_targets, get_local_ip,
)
from host_discovery import discover_alive_hosts
from port_scanner import scan_ports
from brute_force import auto_brute_force
from exploits import _vuln_interactive
from post_exploitation import post_exploit_shell
from reports import (
    generate_summary, export_json, export_csv, export_html,
    _target_to_filename,
)

# Web 扫描模块 (可选)
try:
    from web_scanner import (
        scan_web_hosts, export_web_json, export_web_csv, export_web_html,
        load_web_path_dict,
    )
    WEB_SCANNER_AVAILABLE = True
except ImportError:
    WEB_SCANNER_AVAILABLE = False


# ============================================================================
# Banner
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
    ║                服务识别 | 漏洞检测 | Web扫描 | 报告生成          ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


# ============================================================================
# 交互式模式
# ============================================================================

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

    # Web 应用扫描
    web_results = None
    if WEB_SCANNER_AVAILABLE:
        web_choice = input("\n是否进行 Web 应用扫描? (y/n) [默认: n]: ").strip().lower()
        if web_choice in ("y", "yes"):
            dir_choice = input("跳过目录爆破? (y/n) [默认: n]: ").strip().lower()
            sqli_choice = input("跳过SQL注入检测? (y/n) [默认: n]: ").strip().lower()
            xss_choice = input("跳过XSS检测? (y/n) [默认: n]: ").strip().lower()
            web_results = scan_web_hosts(
                hosts,
                path_dict=None,
                dir_threads=50,
                timeout=timeout,
                skip_dir=(dir_choice in ("y", "yes")),
                skip_sqli=(sqli_choice in ("y", "yes")),
                skip_xss=(xss_choice in ("y", "yes")),
            )

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
        export_html(hosts, f"{base_name}.html", web_results=web_results)

    print(f"\n{'='*60}")
    print(f"  扫描完成! 总耗时: {total_time:.1f}s")
    print(f"  存活: {sum(1 for h in hosts if h.is_alive)}/{len(hosts)} 台")
    print(f"  开放端口: {sum(len(h.open_ports) for h in hosts)} 个")
    print(f"{'='*60}")


# ============================================================================
# 命令行主函数
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="全网段端口扫描器 - 多功能网络安全扫描工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python main.py -t 192.168.1.0/24 -p 1-1000
  python main.py -t 10.0.0.1-10.0.0.254 -p common
  python main.py -t example.com,www.test.com -p 22,80,443
  python main.py -t 192.168.1.1,192.168.1.2 -p 80,443,3306 -o json,html
  python main.py -t 192.168.1.0/24 -p all --no-ping --threads 1000
  python main.py -t 192.168.1.0/24 --brute
  python main.py -t 192.168.1.0/24 --web-scan
  python main.py -t 192.168.1.0/24 -p common --web-scan --web-dir-threads 100
  python main.py  (交互模式)
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
    parser.add_argument(
        "--web-scan", action="store_true", default=False,
        help="启用 Web 应用扫描 (目录爆破/CMS指纹/WAF识别/SQL注入/XSS检测)"
    )
    parser.add_argument(
        "--web-dict", default=None,
        help="自定义 Web 目录字典路径 (每行一个路径)"
    )
    parser.add_argument(
        "--web-dir-threads", type=int, default=50,
        help="目录爆破并发线程数 (默认: 50)"
    )
    parser.add_argument(
        "--web-skip-dir", action="store_true", default=False,
        help="跳过目录爆破"
    )
    parser.add_argument(
        "--web-skip-sqli", action="store_true", default=False,
        help="跳过 SQL 注入检测"
    )
    parser.add_argument(
        "--web-skip-xss", action="store_true", default=False,
        help="跳过 XSS 检测"
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
        port_label = "自定义"

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

    # 漏洞利用
    if args.eternal_blue:
        _vuln_interactive(hosts)

    # Web 应用扫描
    web_results = None
    if args.web_scan:
        if WEB_SCANNER_AVAILABLE:
            web_dict = None
            if args.web_dict:
                web_dict = load_web_path_dict(args.web_dict)
            web_results = scan_web_hosts(
                hosts,
                path_dict=web_dict,
                dir_threads=args.web_dir_threads,
                timeout=args.timeout,
                skip_dir=args.web_skip_dir,
                skip_sqli=args.web_skip_sqli,
                skip_xss=args.web_skip_xss,
            )
        else:
            print("[!] Web 扫描模块未找到, 请确保 web_scanner.py 在同一目录下")

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
        export_html(hosts, f"{base_name}.html", web_results=web_results)

    print(f"\n{'='*60}")
    print(f"  扫描完成! 总耗时: {total_time:.1f}s")
    print(f"{'='*60}")


# ============================================================================
# 入口
# ============================================================================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] 用户中断扫描")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] 错误: {e}")
        sys.exit(1)
