#!/usr/bin/env python3
"""
报告生成模块 - 全网段端口扫描器

从 main.py 提取的报告生成函数:
  - generate_summary: 生成终端扫描摘要
  - export_json / export_csv / export_html: 导出 JSON/CSV/HTML 报告
  - _target_to_filename: 目标IP转为安全文件名
  - _safe_csv_str / _csv_quote: CSV 辅助函数
  - _html_escape: HTML 转义辅助函数
  - _print_open_port: 打印开放端口信息
"""

import json
import os
import time
from collections import defaultdict
from datetime import datetime
from typing import List, Any

from core import HostInfo, ScanResult, get_service_name, ip_to_int, get_local_ip


# ============================================================================
# 打印
# ============================================================================

def _print_open_port(result: ScanResult):
    """打印开放的端口信息"""
    vuln_flag = " [!!!高危] " if result.is_vulnerable else ""
    banner_short = result.banner[:60].replace("\n", " ").replace("\r", "") if result.banner else ""
    print(f"  [+] {result.host:<16} {result.port:<6}/{result.protocol:<4} "
          f"{result.service:<22}{vuln_flag} {banner_short}")


# ============================================================================
# 摘要
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


# ============================================================================
# 文件名工具
# ============================================================================

def _target_to_filename(target: str) -> str:
    """将目标字符串转为安全的文件名前缀"""
    safe = target.replace("/", "_").replace("\\", "_").replace(":", "_")
    safe = safe.replace("*", "_").replace("?", "_").replace('"', "_")
    safe = safe.replace("<", "_").replace(">", "_").replace("|", "_")
    safe = safe.replace(" ", "_")
    safe = safe[:60]
    return safe.strip("_")


# ============================================================================
# JSON 导出
# ============================================================================

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


# ============================================================================
# CSV 辅助函数
# ============================================================================

def _safe_csv_str(val: Any) -> str:
    """将值转为安全的CSV字符串, 去除换行、回车、双引号"""
    s = str(val)
    return s.replace("\n", " ").replace("\r", " ").replace('"', "'")


def _csv_quote(val: str) -> str:
    """将字符串用双引号包裹"""
    return '"' + val + '"'


# ============================================================================
# CSV 导出
# ============================================================================

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


# ============================================================================
# HTML 辅助函数
# ============================================================================

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


# ============================================================================
# HTML 统一报告导出（端口扫描 + Web扫描）
# ============================================================================

def export_html(hosts: List[HostInfo], filepath: str, web_results=None):
    """导出统一 HTML 可视化报告（端口扫描 + 可选 Web 扫描）

    Args:
        hosts: 主机信息列表
        filepath: 输出文件路径
        web_results: Web扫描结果字典 (可选) { "ip:port": WebScanResult }
    """
    alive_hosts = [h for h in hosts if h.is_alive or h.open_ports]
    total_open = sum(len(h.open_ports) for h in hosts)
    vuln_count = sum(sum(1 for p in h.open_ports if p.is_vulnerable) for h in hosts)
    brute_ok = sum(sum(1 for p in h.open_ports if p.brute_result and p.brute_result.success) for h in hosts)
    eb_count = sum(sum(1 for p in h.open_ports if p.eternal_blue_vuln) for h in hosts)
    avg_rtt = 0.0
    all_rtt = [r.response_time * 1000 for h in hosts for r in h.open_ports if r.response_time > 0]
    if all_rtt:
        avg_rtt = sum(all_rtt) / len(all_rtt)

    scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # ============================================================
    # 1. 端口扫描 - 热门开放端口 Top 20
    # ============================================================
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
            <td><div class="bar-wrap"><div class="bar" style="width:{pct}%"></div></div></td>
        </tr>"""

    # ============================================================
    # 2. 端口扫描 - 服务分布 Top 15
    # ============================================================
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
            <td><div class="bar-wrap"><div class="bar bar-blue" style="width:{pct}%"></div></div></td>
        </tr>"""

    # ============================================================
    # 3. 端口扫描 - 主机与端口详情
    # ============================================================
    hosts_html = ""
    for idx, host in enumerate(sorted(alive_hosts, key=lambda h: ip_to_int(h.ip))):
        port_rows = ""
        for r in host.open_ports:
            row_class = "row-danger" if r.is_vulnerable else ""
            # 区分已确认/未确认
            if r.is_vulnerable:
                # 检查 vuln_reason 或 vuln_findings 中是否有已确认的
                is_confirmed = False
                if "已确认" in (r.vuln_reason or ""):
                    is_confirmed = True
                if r.vuln_findings:
                    for vdef in r.vuln_findings.values():
                        if vdef.get("confirmed"):
                            is_confirmed = True
                            break
                if is_confirmed:
                    vuln_badge = ('<span class="tag tag-confirmed">已确认</span>')
                else:
                    vuln_badge = ('<span class="tag tag-suspect">未确认</span>')
            else:
                vuln_badge = ""
            brute_badge = ""
            if r.brute_result and r.brute_result.success:
                brute_badge = (f'<span class="tag tag-crack">[爆破] {r.brute_result.username}/'
                               f'{r.brute_result.password}</span>')
            eb_badge = ""
            if r.eternal_blue_vuln:
                eb_badge = f'<span class="tag tag-eb">[永恒之蓝] {_html_escape(r.eternal_blue_os)}</span>'

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
                    <th style="width:80px">端口</th>
                    <th style="width:110px">服务</th>
                    <th style="width:90px">状态</th>
                    <th style="width:75px">响应</th>
                    <th style="width:55px">TTL</th>
                    <th style="width:100px">版本</th>
                    <th>Banner / 指纹</th>
                    <th style="width:180px">风险与爆破</th>
                </tr></thead>
                <tbody>{port_rows}</tbody>
            </table>
            </div>
        </div>"""

    if not hosts_html:
        hosts_html = '<div class="empty-state"><div class="empty-icon">🖥</div><p>暂无存活主机或有开放端口</p></div>'

    # ============================================================
    # 4. Web 扫描部分
    # ============================================================
    web_section = ""
    has_web = False
    if web_results:
        has_web = True
        # Web 统计
        web_target_count = len(web_results)
        web_dir_count = sum(len(r.discovered_dirs) for r in web_results.values())
        web_vuln_count = sum(len(r.vulnerabilities) for r in web_results.values())
        web_cms_count = sum(1 for r in web_results.values() if r.cms.cms)
        web_waf_count = sum(1 for r in web_results.values() if r.waf.waf)

        # Web 目标概览表
        web_targets_html = ""
        for r in web_results.values():
            t = r.target
            cms_str = ""
            if r.cms.cms:
                ver = f" {r.cms.version}" if r.cms.version else ""
                cms_str = (f'<span class="tag tag-cms">{r.cms.cms}{ver}</span> '
                           f'<span class="confidence">({r.cms.confidence})</span>')

            waf_str = ""
            if r.waf.waf:
                waf_str = (f'<span class="tag tag-waf">🛡 {r.waf.waf}</span> '
                           f'<span class="confidence">({r.waf.confidence})</span>')

            vuln_str = "—"
            if r.vulnerabilities:
                vuln_str = ""
                for v in r.vulnerabilities:
                    vuln_str += (f'<span class="tag tag-webvuln">{v.vuln_type}</span> '
                                 f'<span class="vuln-evidence">{_html_escape(v.evidence[:100])}</span><br>')

            status_cls = "status-ok" if r.status_code < 400 else "status-warn" if r.status_code < 500 else "status-err"

            web_targets_html += f"""
            <tr>
                <td class="url-cell"><a href="{t.base_url}" target="_blank" rel="noopener">🔗 {t.base_url}</a></td>
                <td><span class="{status_cls}">{r.status_code}</span></td>
                <td>{_html_escape(r.server_header) or '—'}</td>
                <td class="title-cell">{_html_escape(r.title[:50]) if r.title else '—'}</td>
                <td>{cms_str or '<span class="muted">—</span>'}</td>
                <td>{waf_str or '<span class="muted">—</span>'}</td>
                <td class="num-cell">{len(r.discovered_dirs)}</td>
                <td>{vuln_str}</td>
            </tr>"""

        # Web 发现目录表
        web_dirs_html = ""
        for r in web_results.values():
            for d in sorted(r.discovered_dirs, key=lambda x: x.status):
                status_cls = ""
                if d.status in (200, 301, 302, 307):
                    status_cls = "row-web-dir-found"
                elif d.status in (401, 403):
                    status_cls = "row-web-dir-access"
                size_kb = f"{d.size / 1024:.1f} KB" if d.size > 1024 else f"{d.size} B"
                redirect_html = ""
                if d.redirect:
                    redirect_html = (f' <span class="redirect-arrow">→</span> '
                                     f'<span class="redirect-url">{_html_escape(d.redirect[:60])}</span>')

                web_dirs_html += f"""
                <tr class="{status_cls}">
                    <td><code>{r.target.host}:{r.target.port}</code></td>
                    <td class="status-code status-{d.status}">{d.status}</td>
                    <td class="path-cell"><code>{_html_escape(d.path)}</code></td>
                    <td class="size-cell">{size_kb}</td>
                    <td>{redirect_html if redirect_html else '<span class="muted">—</span>'}</td>
                </tr>"""

        web_section = f"""
        <div class="section web-section">
            <h2>🌐 Web 应用扫描 <span class="count">({web_target_count} 个目标)</span></h2>

            <h3 class="sub-heading">📊 Web 目标概览</h3>
            <div class="table-scroll">
            <table>
                <thead><tr>
                    <th style="width:250px">URL</th>
                    <th style="width:60px">状态码</th>
                    <th style="width:160px">Server</th>
                    <th style="width:180px">Title</th>
                    <th style="width:160px">CMS</th>
                    <th style="width:150px">WAF</th>
                    <th style="width:60px">目录数</th>
                    <th>漏洞</th>
                </tr></thead>
                <tbody>{web_targets_html}</tbody>
            </table>
            </div>

            <h3 class="sub-heading">📁 发现目录详情 <span class="count">({web_dir_count} 个)</span></h3>
            <div class="table-scroll">
            <table>
                <thead><tr>
                    <th style="width:180px">主机</th>
                    <th style="width:70px">状态码</th>
                    <th>路径</th>
                    <th style="width:80px">大小</th>
                    <th style="width:220px">重定向</th>
                </tr></thead>
                <tbody>{web_dirs_html if web_dirs_html else '<tr><td colspan="5" class="muted" style="text-align:center">无已发现目录</td></tr>'}</tbody>
            </table>
            </div>
        </div>"""

    # ============================================================
    # 组合完整 HTML
    # ============================================================
    # Web 额外统计卡
    web_stats_html = ""
    if has_web:
        web_stats_html = f"""
            <div class="stat-card web">
                <div class="value">{web_target_count}</div>
                <div class="label">🌐 Web 目标</div>
            </div>
            <div class="stat-card web">
                <div class="value">{web_dir_count}</div>
                <div class="label">📁 发现目录</div>
            </div>
            <div class="stat-card web">
                <div class="value">{web_cms_count}</div>
                <div class="label">🧩 CMS 识别</div>
            </div>
            <div class="stat-card web">
                <div class="value">{web_waf_count}</div>
                <div class="label">🛡 WAF 识别</div>
            </div>
            <div class="stat-card danger">
                <div class="value">{web_vuln_count}</div>
                <div class="label">🐛 Web 漏洞</div>
            </div>"""

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>全网段端口扫描报告 - {scan_time}</title>
<style>
/* ===== 基础与暗色主题 ===== */
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: 'Segoe UI', 'Microsoft YaHei', system-ui, sans-serif;
    background: #0a0e14; color: #c9d1d9; padding: 24px; line-height: 1.5;
    min-height: 100vh;
}}
.container {{ max-width: 1600px; margin: 0 auto; }}

/* ===== 顶部导航 ===== */
.nav-bar {{
    display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 20px;
    padding: 12px 20px; background: #161b22; border-radius: 10px;
    border: 1px solid #30363d;
}}
.nav-bar a {{
    color: #58a6ff; text-decoration: none; padding: 6px 16px;
    border-radius: 6px; font-size: .88em; transition: all .15s;
    white-space: nowrap;
}}
.nav-bar a:hover {{ background: #1c2a3a; color: #79c0ff; }}

/* ===== 头部 ===== */
.header {{
    background: linear-gradient(135deg, #0d1b2a 0%, #13223a 50%, #0f2940 100%);
    padding: 40px 48px; border-radius: 14px; margin-bottom: 24px;
    border: 1px solid #21262d; position: relative; overflow: hidden;
}}
.header::before {{
    content: ''; position: absolute; top: -60%; right: -30%;
    width: 350px; height: 350px;
    background: radial-gradient(circle, rgba(88,166,255,0.08) 0%, transparent 70%);
    border-radius: 50%;
}}
.header::after {{
    content: ''; position: absolute; bottom: -40%; left: -20%;
    width: 280px; height: 280px;
    background: radial-gradient(circle, rgba(163,113,247,0.06) 0%, transparent 70%);
    border-radius: 50%;
}}
.header h1 {{
    color: #58a6ff; font-size: 2em; margin-bottom: 10px;
    position: relative; font-weight: 700; letter-spacing: 1px;
}}
.header p {{ color: #8b949e; position: relative; font-size: .92em; }}

/* ===== 统计卡片 ===== */
.stats {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(155px, 1fr));
    gap: 14px; margin-bottom: 24px;
}}
.stat-card {{
    background: #161b22; padding: 22px 16px; border-radius: 10px;
    border: 1px solid #21262d; text-align: center;
    transition: all .2s; cursor: default;
}}
.stat-card:hover {{
    transform: translateY(-3px); border-color: #30363d;
    box-shadow: 0 4px 20px rgba(0,0,0,.3);
}}
.stat-card .value {{
    font-size: 2.4em; font-weight: 800; color: #58a6ff; line-height: 1;
}}
.stat-card .label {{
    color: #8b949e; margin-top: 8px; font-size: .85em;
    text-transform: uppercase; letter-spacing: .5px;
}}
.stat-card.danger .value {{ color: #f85149; }}
.stat-card.danger {{ border-color: #f8514922; }}
.stat-card.crack .value {{ color: #d2a847; }}
.stat-card.crack {{ border-color: #d2a84722; }}
.stat-card.rtt .value {{ color: #7ee787; }}
.stat-card.rtt {{ border-color: #7ee78722; }}
.stat-card.web .value {{ color: #a371f7; }}
.stat-card.web {{ border-color: #a371f722; }}
.stat-card.web:hover {{ border-color: #a371f744; }}

/* ===== 段落标题 ===== */
.section {{
    background: #161b22; padding: 28px 32px; border-radius: 12px;
    border: 1px solid #21262d; margin-bottom: 24px;
}}
.section h2 {{
    color: #58a6ff; font-size: 1.25em; margin-bottom: 20px;
    display: flex; align-items: center; gap: 10px;
    font-weight: 700;
}}
.section h2::before {{
    content: ''; display: inline-block; width: 4px; height: 20px;
    background: #58a6ff; border-radius: 2px;
}}
.section h2 .count {{
    color: #8b949e; font-size: .65em; font-weight: normal;
    margin-left: auto;
}}
.sub-heading {{
    color: #c9d1d9; font-size: 1.05em; margin: 24px 0 14px;
    font-weight: 600; padding-bottom: 8px; border-bottom: 1px solid #21262d;
}}

/* ===== 表格 ===== */
.table-scroll {{ overflow-x: auto; }}
table {{ width: 100%; border-collapse: collapse; font-size: .89em; }}
th, td {{ padding: 11px 14px; text-align: left; border-bottom: 1px solid #21262d; }}
th {{
    background: #0d1117; color: #8b949e; font-weight: 600; font-size: .82em;
    white-space: nowrap; text-transform: uppercase; letter-spacing: .3px;
}}
tr:hover {{ background: #1a2029; }}
.port-num {{ font-weight: 700; color: #58a6ff; }}
.num-cell {{ text-align: center; font-weight: 600; color: #a371f7; }}

/* ===== 条形图 ===== */
.bar-wrap {{ background: #21262d; border-radius: 4px; height: 10px; overflow: hidden; min-width: 60px; }}
.bar {{ background: #238636; height: 100%; border-radius: 4px; transition: width .4s ease; min-width: 3px; }}
.bar-blue {{ background: #58a6ff; }}

/* ===== 主机分组 ===== */
.host-group {{
    margin-bottom: 10px; border: 1px solid #21262d; border-radius: 8px; overflow: hidden;
    transition: border .2s;
}}
.host-group:hover {{ border-color: #30363d; }}
.host-group-header {{
    display: flex; align-items: center; gap: 14px; padding: 14px 20px;
    background: #0d1117; cursor: pointer; user-select: none;
    border-bottom: 1px solid #21262d; transition: background .15s;
}}
.host-group-header:hover {{ background: #131a24; }}
.host-arrow {{
    color: #58a6ff; transition: transform .25s; font-size: 1em;
    display: inline-block; width: 16px; text-align: center;
}}
.host-content.collapsed {{ display: none; }}
.host-ip {{
    color: #58a6ff; font-weight: 700; font-size: 1.08em; min-width: 130px;
    font-family: 'Consolas', 'Courier New', monospace;
}}
.host-hostname {{ color: #8b949e; min-width: 100px; font-size: .9em; }}
.host-os {{ color: #7ee787; font-size: .85em; }}
.host-stats {{ color: #484f58; font-size: .8em; margin-left: auto; white-space: nowrap; }}

/* ===== 端口表格 ===== */
.port-table {{ font-size: .86em; }}
.port-table th {{ padding: 8px 10px; }}
.port-table td {{ padding: 7px 10px; vertical-align: top; }}
.port-cell {{ white-space: nowrap; }}
.port-badge {{
    display: inline-block; background: #238636; color: #fff; padding: 3px 10px;
    border-radius: 5px; font-weight: 700; font-size: .92em;
    min-width: 42px; text-align: center;
}}
.port-badge-danger {{
    background: #da3633;
    animation: dangerPulse 2.5s infinite;
}}
@keyframes dangerPulse {{
    0%, 100% {{ box-shadow: 0 0 0 0 rgba(218,54,51,.4); }}
    50% {{ box-shadow: 0 0 0 6px rgba(218,54,51,0); }}
}}
.proto-tag {{ color: #8b949e; font-size: .72em; margin-left: 6px; }}

/* ===== 状态颜色 ===== */
.state-open {{ color: #3fb950; font-weight: 600; }}
.state-closed {{ color: #8b949e; }}
.state-filtered {{ color: #d29922; }}
.state-open\\|filtered {{ color: #d29922; }}
.status-ok {{ color: #3fb950; font-weight: 600; }}
.status-warn {{ color: #d29922; font-weight: 600; }}
.status-err {{ color: #f85149; font-weight: 600; }}
.muted {{ color: #484f58; font-style: italic; }}

/* ===== 版本与指纹 ===== */
.version-cell {{ max-width: 140px; }}
.version {{ color: #a5d6ff; font-size: .83em; word-break: break-all; }}
.fingerprint-cell {{ max-width: 420px; }}
.fingerprint-preview {{
    color: #8b949e; font-size: .8em;
    font-family: 'Consolas', 'Cascadia Code', 'Courier New', monospace;
    max-height: 55px; overflow: hidden; white-space: pre-wrap;
    word-break: break-all; line-height: 1.4;
}}
.fingerprint-preview:hover {{ max-height: none; }}

/* ===== 风险标签 ===== */
.risk-cell {{ white-space: nowrap; }}
.row-danger {{ background: #f8514906; }}
.tag {{
    display: inline-block; padding: 3px 10px; border-radius: 5px;
    font-size: .8em; margin: 2px 4px 2px 0; font-weight: 600;
    letter-spacing: .3px;
}}
.tag-danger {{ background: #da363318; color: #f85149; border: 1px solid #da363344; }}
.tag-confirmed {{
    background: #f8514920; color: #f85149; border: 1px solid #f85149;
    font-weight: 700; animation: dangerPulse 2.5s infinite;
}}
.tag-suspect {{
    background: #d2992220; color: #d29922; border: 1px solid #d2992255;
}}
.tag-crack {{ background: #d2a84718; color: #d2a847; border: 1px solid #d2a84744; }}
.tag-eb {{
    background: #e9456018; color: #e94560; border: 1px solid #e9456044;
    animation: dangerPulse 2s infinite;
}}
.tag-cms {{ background: #1a527618; color: #85c1e9; border: 1px solid #1a527644; }}
.tag-waf {{ background: #7d3c9818; color: #b39ddb; border: 1px solid #7d3c9844; }}
.tag-webvuln {{ background: #922b2118; color: #f1948a; border: 1px solid #922b2144; }}
.confidence {{ color: #484f58; font-size: .75em; }}
.vuln-detail {{ color: #f8514988; font-size: .76em; margin-top: 4px; white-space: normal; }}
.vuln-evidence {{ color: #8b949e; font-size: .8em; }}

/* ===== Web 扫描特殊样式 ===== */
.url-cell {{ max-width: 280px; }}
.url-cell a {{ color: #85c1e9; text-decoration: none; word-break: break-all; }}
.url-cell a:hover {{ color: #58a6ff; text-decoration: underline; }}
.title-cell {{ max-width: 160px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
.path-cell {{ max-width: 400px; }}
.path-cell code {{
    background: #21262d; padding: 2px 8px; border-radius: 4px;
    font-size: .9em; color: #a371f7;
}}
.size-cell {{ white-space: nowrap; font-family: monospace; font-size: .85em; }}
.redirect-arrow {{ color: #d29922; margin: 0 4px; }}
.redirect-url {{ color: #d2992288; font-size: .82em; }}
.status-code.status-200 {{ color: #3fb950; font-weight: 600; }}
.status-code.status-301, .status-code.status-302, .status-code.status-307 {{ color: #58a6ff; font-weight: 600; }}
.status-code.status-401, .status-code.status-403 {{ color: #d29922; font-weight: 600; }}
.status-code.status-500, .status-code.status-502, .status-code.status-503 {{ color: #f85149; font-weight: 600; }}
.row-web-dir-found {{ border-left: 3px solid #3fb950; }}
.row-web-dir-access {{ border-left: 3px solid #d29922; }}

/* ===== Web 区域 ===== */
.web-section h2::before {{ background: #a371f7; }}
.web-section h2 {{ color: #a371f7; }}

/* ===== 空状态 ===== */
.empty-state {{
    text-align: center; color: #484f58; padding: 80px 20px; font-size: 1.1em;
}}
.empty-icon {{ font-size: 3em; margin-bottom: 16px; opacity: .5; }}

/* ===== 页脚 ===== */
.footer {{
    text-align: center; color: #30363d; padding: 36px 0 16px;
    font-size: .84em; border-top: 1px solid #21262d; margin-top: 10px;
}}
.footer p + p {{ margin-top: 6px; }}

/* ===== 响应式 ===== */
@media (max-width: 900px) {{
    body {{ padding: 12px; }}
    .stats {{ grid-template-columns: repeat(2, 1fr); }}
    .header {{ padding: 24px 20px; }}
    .section {{ padding: 16px 14px; }}
    .host-group-header {{ flex-wrap: wrap; gap: 8px; }}
    .host-stats {{ margin-left: 0; width: 100%; text-align: left; }}
    .nav-bar {{ overflow-x: auto; flex-wrap: nowrap; padding: 10px 12px; }}
}}
</style>
</head>
<body>
<div class="container">

<!-- 顶部导航 -->
<div class="nav-bar">
    <a href="#stats">📈 概览统计</a>
    <a href="#top-ports">🔝 热门端口</a>
    <a href="#services">📋 服务分布</a>
    <a href="#hosts">🖥 主机详情</a>
    {f'<a href="#web-scan">🌐 Web 扫描</a>' if has_web else ''}
</div>

<!-- 头部 -->
<div class="header">
    <h1>🔍 全网段端口扫描报告</h1>
    <p>📅 扫描时间: {scan_time} &nbsp;|&nbsp;
       💻 扫描器 IP: {get_local_ip()} &nbsp;|&nbsp;
       🟢 存活 {len(alive_hosts)}/{len(hosts)} 台 &nbsp;|&nbsp;
       🔌 开放端口: {total_open} &nbsp;|&nbsp;
       ⚠ 高危端口: {vuln_count}</p>
</div>

<!-- 统计卡片 -->
<div class="stats" id="stats">
    <div class="stat-card">
        <div class="value">{len(hosts)}</div>
        <div class="label">📊 总目标数</div>
    </div>
    <div class="stat-card">
        <div class="value">{len(alive_hosts)}</div>
        <div class="label">🟢 存活主机</div>
    </div>
    <div class="stat-card">
        <div class="value">{total_open}</div>
        <div class="label">🔌 开放端口</div>
    </div>
    <div class="stat-card danger">
        <div class="value">{vuln_count}</div>
        <div class="label">⚠ 高危端口</div>
    </div>
    <div class="stat-card crack">
        <div class="value">{brute_ok}</div>
        <div class="label">🔑 爆破成功</div>
    </div>
    <div class="stat-card danger">
        <div class="value">{eb_count}</div>
        <div class="label">💀 MS17-010</div>
    </div>
    <div class="stat-card rtt">
        <div class="value">{avg_rtt:.1f}ms</div>
        <div class="label">⏱ 平均响应</div>
    </div>
    {web_stats_html}
</div>

<!-- 热门端口 -->
<div class="section" id="top-ports">
    <h2>🔝 热门开放端口 <span class="count">Top {min(20, len(top_ports))}</span></h2>
    <div class="table-scroll">
    <table>
        <thead><tr><th>端口</th><th>服务名称</th><th>出现主机数</th><th>分布占比</th></tr></thead>
        <tbody>{top_ports_html if top_ports_html else '<tr><td colspan="4" class="muted" style="text-align:center">无开放端口</td></tr>'}</tbody>
    </table>
    </div>
</div>

<!-- 服务分布 -->
<div class="section" id="services">
    <h2>📋 服务分布 <span class="count">Top {min(15, len(top_svcs))}</span></h2>
    <div class="table-scroll">
    <table>
        <thead><tr><th>服务类型</th><th>出现次数</th><th>分布占比</th></tr></thead>
        <tbody>{svc_dist_html if svc_dist_html else '<tr><td colspan="3" class="muted" style="text-align:center">无服务数据</td></tr>'}</tbody>
    </table>
    </div>
</div>

<!-- 主机详情 -->
<div class="section" id="hosts">
    <h2>🖥 主机与端口详情 <span class="count">{len(alive_hosts)} 台存活 · {total_open} 个端口</span></h2>
    <p style="color:#8b949e; margin-bottom:18px; font-size:.85em;">
       💡 点击主机行展开/折叠端口 | 鼠标悬停 Banner 查看完整指纹 | 红色 = 高危
    </p>
    {hosts_html}
</div>

<!-- Web 扫描 -->
{web_section}

<!-- 页脚 -->
<div class="footer">
    <p>🚀 全网段端口扫描器 v3.0 | Powered by Python Standard Library</p>
    <p>TCP/UDP · ICMP · CIDR · Banner · OS指纹 · 弱口令爆破 · 漏洞利用 · Web扫描 · 报告生成</p>
</div>

</div>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8-sig") as f:
        f.write(html)
    print(f"[+] 统一 HTML 报告已保存: {filepath}")
