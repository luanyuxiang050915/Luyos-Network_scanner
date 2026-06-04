# 全网段端口扫描器 v3.0

多功能网络安全扫描与渗透测试工具，模块化架构，集端口扫描、Web扫描、弱口令爆破、漏洞利用、后渗透于一体。

> **免责声明**: 本工具仅供网络安全学习、授权测试及合法安全评估使用。使用者需自行承担法律责任。

---

## 功能特性

| 模块 | 说明 |
|------|------|
| **主机发现** | ICMP Ping + TCP 多端口 Ping，自动识别存活主机 |
| **端口扫描** | 多线程 TCP Connect + UDP 扫描，支持 1-65535 全端口 |
| **Banner 抓取** | 对开放端口发送针对性探测包，抓取服务 Banner |
| **服务/版本识别** | 内置 140+ 端口服务映射表，正则提取软件版本 |
| **OS 猜测** | 通过 TTL 值推测操作系统 (Windows / Linux / 网络设备等) |
| **Web 应用扫描** | 目录爆破 · CMS 指纹 (WordPress/Joomla/Drupal等) · WAF 识别 (Cloudflare/AWS等) · SQL 注入检测 · XSS 检测 |
| **弱口令爆破** | 支持 **FTP · SSH · Telnet · MySQL · MSSQL · RDP · PostgreSQL** 共 7 种协议 |
| **漏洞检测** | EternalBlue · BlueKeep · Redis/Docker/Hadoop/Cisco 未授权访问，**三级确认体系** (待确认/已确认/风险提示) |
| **漏洞利用** | 自动利用已确认漏洞，支持 EternalBlue 后渗透 |
| **后渗透 Shell** | SMB/DCERPC/SCM 交互式 Shell，类似 MSF `sessions -i` |
| **报告导出** | JSON · CSV · **统一 HTML** (暗色主题，端口+Web合并，导航栏，统计卡片) |

---

## 项目结构

```
Luyos-Network_scanner/
├── main.py              # 入口 (CLI + 交互模式)
├── config.py            # 全局常量 (端口映射/漏洞库/爆破字典等)
├── core.py              # 数据结构 + 公共工具函数
├── host_discovery.py    # 主机发现 (ICMP/TCP Ping)
├── port_scanner.py      # TCP/UDP 端口扫描 + Banner抓取 + 扫描引擎
├── brute_force.py       # 弱口令爆破 (7种协议)
├── exploits.py          # 漏洞检测与利用 (6种漏洞)
├── post_exploitation.py # 后渗透 Shell (SMB/DCERPC/SCM)
├── reports.py           # 报告生成 (JSON/CSV/HTML)
├── web_scanner.py       # Web 应用扫描 (目录爆破/CMS/WAF/SQLi/XSS)
├── password_dict.txt    # 密码字典 (133条)
├── requirements.txt     # Python 依赖
├── LICENSE
├── .gitignore
└── reports/             # 报告输出目录 (自动生成)
```

---

## 快速开始

```bash
# 安装依赖
pip install -r requirements.txt

# 命令行模式
python main.py -t 192.168.1.0/24

# 交互模式 (按提示操作)
python main.py
```

---

## 命令行参数

| 参数 | 简写 | 说明 | 默认值 |
|------|------|------|--------|
| `--target` | `-t` | 目标 (IP/域名/CIDR/范围) | 必填 |
| `--ports` | `-p` | `common` / `top1000` / `all` / 自定义 | `common` |
| `--proto` | | `tcp` / `udp` / `both` | `tcp` |
| `--threads` | | 并发线程数 | `500` |
| `--timeout` | | 连接超时(秒) | `2.0` |
| `--no-ping` | | 跳过存活探测 | 关闭 |
| `--ping-method` | | `icmp` / `tcp` / `both` | `both` |
| `--output` | `-o` | `json` / `csv` / `html` / `all` / `none` | `all` |
| `--output-dir` | | 报告输出目录 | `./reports/` |
| `--brute` | | 启用弱口令爆破 (7种协议) | 关闭 |
| `--dict` | | 自定义密码字典路径 | `password_dict.txt` |
| `--eternal-blue` | | 启用漏洞利用阶段 | 关闭 |
| `--web-scan` | | 启用 Web 应用扫描 | 关闭 |
| `--web-dict` | | 自定义 Web 目录字典 | 内置字典 |
| `--web-dir-threads` | | 目录爆破线程数 | `50` |
| `--web-skip-dir` | | 跳过目录爆破 | 关闭 |
| `--web-skip-sqli` | | 跳过 SQL 注入检测 | 关闭 |
| `--web-skip-xss` | | 跳过 XSS 检测 | 关闭 |

---

## 使用示例

### 端口扫描

```bash
# 基础快速扫描
python main.py -t 192.168.1.0/24

# 全端口 + 跳过存活探测 + 1000 线程
python main.py -t 192.168.1.0/24 -p all --no-ping --threads 1000

# 自定义端口 + HTML 报告
python main.py -t 10.0.0.1-10.0.0.254 -p 80,443,3306,3389 -o html

# TCP + UDP 双协议
python main.py -t 192.168.1.0/24 --proto both

# 多目标混合扫描
python main.py -t 192.168.1.0/24,example.com -p 22,80,443
```

### 弱口令爆破 (7种协议)

```bash
# 启用爆破 (自动检测开放的服务端口)
python main.py -t 192.168.1.0/24 --brute

# 自定义密码字典
python main.py -t 192.168.1.0/24 --brute --dict my_passwords.txt
```

### Web 应用扫描

```bash
# 启用 Web 扫描 (目录爆破 + CMS/WAF + SQL注入 + XSS)
python main.py -t 192.168.1.0/24 -p common --web-scan

# 跳过目录爆破，只做指纹和漏洞检测
python main.py -t 192.168.1.0/24 --web-scan --web-skip-dir

# 自定义目录字典 + 100 线程
python main.py -t 192.168.1.0/24 --web-scan --web-dict my_dirs.txt --web-dir-threads 100
```

---

## 目标格式

| 格式 | 示例 | 说明 |
|------|------|------|
| 单个 IP | `192.168.1.1` | 单台主机 |
| 域名 | `example.com` | DNS 解析后扫描 |
| IP 范围 | `192.168.1.1-192.168.1.254` | 连续 IP 段 |
| CIDR 网段 | `192.168.1.0/24` | 扫描子网 |
| 混合 | `192.168.1.1,10.0.0.0/24,example.com` | 逗号分隔 |

---

## 端口扫描模式

| 模式 | 参数 | 端口数 | 场景 |
|------|------|--------|------|
| 快速扫描 | `-p common` | ~200 | 日常巡检 |
| 标准扫描 | `-p top1000` | 1000 | 常规评估 |
| 全端口扫描 | `-p all` | 65535 | 深度审计 |
| 自定义 | `-p 80,443,3306` | 自定义 | 专项检查 |

---

## 漏洞检测体系

采用**三级确认**机制，避免误报：

| 级别 | 说明 | 示例 |
|------|------|------|
| **[已确认]** 红色 | 经过协议级检测确认 | EternalBlue SMBv1 协商成功 |
| **[待确认]** 橙色 | 端口开放但尚未深度检测 | 445开放但 SMBv1 未确认 |
| **[风险提示]** 灰色 | 仅字典匹配，无检测函数 | MySQL 3306 弱口令风险 |

有专门协议检测函数的端口：`445, 3389, 6379, 2375, 8088, 4786`

---

## 弱口令爆破

支持 **7 种协议**，全部纯 Python 实现（除 SSH 可选 paramiko 加速）：

| 协议 | 端口 | 实现方式 |
|------|------|---------|
| FTP | 21 | 纯 socket `USER` → `PASS` 流程 |
| SSH | 22 | paramiko 库 / plink+sshpass 回退 |
| Telnet | 23 | 纯 socket Login/Password 提示符匹配 |
| MySQL | 3306 | 纯 socket `mysql_native_password` |
| MSSQL | 1433 | 纯 socket TDS PRELOGIN + LOGIN7 |
| RDP | 3389 | NLA + NTLMSSP + NTLMv2 认证 |
| PostgreSQL | 5432 | 纯 socket MD5 认证 (SCRAM 自动跳过) |

内置 **133 条**常用弱口令字典（`password_dict.txt`），支持 `--dict` 自定义。

---

## Web 应用扫描

| 功能 | 说明 |
|------|------|
| **目录爆破** | 内置 100+ 常见路径字典，50 线程并发 |
| **CMS 指纹** | WordPress / Joomla / Drupal / Tomcat / phpMyAdmin / Nginx / IIS / Apache 等 |
| **WAF 识别** | Cloudflare / ModSecurity / AWS WAF / Imperva / Sucuri / F5 / FortiWeb / 阿里云 / 知道创宇等 |
| **SQL 注入** | 8 种 payload，覆盖 MySQL / PostgreSQL / Oracle / MSSQL / SQLite |
| **XSS** | 4 种 payload 反射型检测 |

---

## 漏洞利用 & 后渗透

| 漏洞 | 说明 |
|------|------|
| EternalBlue (MS17-010) | SMBv1 检测 + 漏洞利用 + 后渗透 Shell |
| BlueKeep (CVE-2019-0708) | RDP 协议检测 |
| Redis 未授权 | PING 检测 + 信息获取 |
| Docker Remote API | 容器列表 + Docker 信息 |
| Hadoop YARN | 未授权 RCE |
| Cisco Smart Install | CVE-2018-0171 |

```bash
# 启用漏洞利用交互
python main.py -t 192.168.1.0/24 --eternal-blue
```

### 后渗透 Shell

```python
from post_exploitation import post_exploit_shell

# 直接连接目标
post_exploit_shell("192.168.1.100", username="administrator", password="123456")
```

---

## 报告导出

统一 **一份 HTML 报告**包含所有结果（端口扫描 + Web 扫描），暗色主题。

| 格式 | 特点 |
|------|------|
| **HTML** | 暗色主题可视化 · 顶部导航栏 · 统计卡片 · 端口/服务分布 · 可折叠主机详情 · Web扫描结果 · 已确认/待确认区分 |
| **JSON** | 完整结构化数据 |
| **CSV** | 表格格式，18 列字段 |

---

## 依赖

| 依赖 | 说明 | 必需 |
|------|------|------|
| Python 3.6+ | 运行环境 | ✓ |
| impacket ≥ 0.13.1 | SMBv2 / DCERPC (后渗透) | ✓ |
| pyasn1 ≥ 0.6.0 | ASN.1 (impacket 依赖) | ✓ |
| pycryptodome ≥ 3.20.0 | 加密算法 (NTLM) | ✓ |
| paramiko | SSH 爆破加速 | 可选 |

```bash
pip install -r requirements.txt
pip install paramiko  # 可选
```

---

## License

[MIT License](LICENSE)

仅供学习和合法授权测试使用。
