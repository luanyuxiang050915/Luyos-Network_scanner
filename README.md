# 全网段端口扫描器

多功能网络安全扫描与渗透测试工具，集端口扫描、漏洞利用、后渗透 Shell 于一体。

> **免责声明**: 本工具仅供网络安全学习、授权测试及合法安全评估使用。使用者需自行承担法律责任。

---

## 功能特性

| 模块 | 说明 |
|------|------|
| **主机发现** | ICMP Ping + TCP 多端口 Ping，自动识别存活主机 |
| **端口扫描** | 多线程 TCP Connect 扫描 + UDP 扫描，支持 1-65535 全端口 |
| **Banner 抓取** | 对开放端口发送针对性探测包，抓取服务 Banner |
| **服务识别** | 内置 140+ 端口服务映射表 + 系统 `getservbyport` 补充 |
| **版本识别** | 从 Banner 中正则提取 SSH / HTTP / 服务器等软件版本 |
| **Web 指纹** | 识别 Apache / Nginx / IIS / Tomcat / Jetty 等 Web 服务器 |
| **漏洞标记** | 内置 60+ 高危端口库（关联 CVE），红色高亮标记 |
| **OS 猜测** | 通过 TTL 值推测操作系统（Windows / Linux / 网络设备等） |
| **弱口令爆破** | SSH / MySQL / MSSQL 自动弱口令爆破 |
| **漏洞利用** | EternalBlue (MS17-010) 漏洞检测与自动利用 |
| **后渗透 Shell** | 漏洞利用成功后直接获取交互式 Shell，类似 MSF `sessions -i` |
| **报告导出** | JSON / CSV / HTML 可视化报告三种格式 |
| **进度显示** | 实时显示扫描进度、速率、预计剩余时间 |

---

## 快速开始

```bash
# 安装依赖
pip install -r requirements.txt

# 命令行模式
python main.py -t 192.168.1.0/24
```

---

## 使用方式

### 命令行模式

```bash
# 基础扫描
python main.py -t 192.168.1.0/24

# 全端口扫描 + 跳过存活探测 + 1000 线程
python main.py -t 192.168.1.0/24 -p all --no-ping --threads 1000

# 指定端口 + 导出 HTML 报告
python main.py -t 10.0.0.1-10.0.0.254 -p 80,443,3306 -o html

# TCP + UDP 双协议
python main.py -t 192.168.1.0/24 --proto both

# 启用弱口令爆破 + 自定义字典
python main.py -t 192.168.1.0/24 --brute --dict my_passwords.txt

# 多目标混合扫描
python main.py -t 192.168.1.0/24,example.com -p 22,80,443
```

### 交互模式

```bash
python main.py
```

按提示输入目标地址、端口范围等参数，扫描完成后可选择对发现的主机进行后渗透。

---

## EternalBlue 漏洞利用 & 后渗透 Shell

扫描发现 445 端口开放且存在 MS17-010 漏洞时，可自动利用并获取交互式 Shell。

### 一键操作流程

1. 扫描目标网段，发现 445 端口开放的主机
2. 自动检测 EternalBlue 漏洞（MS17-010）
3. 漏洞利用成功后，输入目标凭据即可获取 Shell

### 独立启动后渗透 Shell

```python
from main import post_exploit_shell

# 直接连接目标获取 Shell
post_exploit_shell("192.168.1.100", username="administrator", password="123456")
```

```bash
# 命令行一键获取 Shell
python -c "from main import post_exploit_shell; post_exploit_shell('192.168.1.100', 'admin', '123456')"
```

### Shell 支持的命令

```
POST [主机名]> whoami              # 当前用户
POST [主机名]> hostname             # 主机名
POST [主机名]> systeminfo           # 系统信息
POST [主机名]> ipconfig             # 网络配置
POST [主机名]> net user             # 用户列表
POST [主机名]> tasklist             # 进程列表
POST [主机名]> <任意 Windows 命令>   # 自定义命令
POST [主机名]> exit / quit          # 退出
```

> **原理**：通过 SMBv2 协议认证后，使用 DCERPC 服务管理（SCM）在目标上创建 Windows 服务来执行命令，输出通过 ADMIN$ 共享回传。

---

## 命令行参数

| 参数 | 简写 | 说明 | 默认值 |
|------|------|------|--------|
| `--target` | `-t` | 目标地址 (IP/域名/CIDR/范围) | 必填 |
| `--ports` | `-p` | `common` / `top1000` / `all` / 自定义 | `common` |
| `--proto` | - | 协议 `tcp` / `udp` / `both` | `tcp` |
| `--threads` | - | 并发线程数 | `500` |
| `--timeout` | - | 连接超时(秒) | `2.0` |
| `--no-ping` | - | 跳过存活探测 | 关闭 |
| `--output` | `-o` | 报告格式 `json` / `csv` / `html` / `all` / `none` | `all` |
| `--output-dir` | - | 报告输出目录 | `./reports/` |
| `--brute` | - | 启用弱口令爆破 | 关闭 |
| `--dict` | - | 自定义密码字典 | `password_dict.txt` |

---

## 目标格式

| 格式 | 示例 | 说明 |
|------|------|------|
| 单个 IP | `192.168.1.1` | 扫描单台主机 |
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

## Banner & 指纹识别

| 端口 | 协议 | 探测方式 |
|------|------|---------|
| 80/8080 | HTTP | `GET / HTTP/1.0` 请求 |
| 443 | HTTPS | ClientHello 握手 |
| 22 | SSH | Banner 读取 |
| 3306 | MySQL | 握手包解析 |
| 6379 | Redis | `PING` 命令 |
| 3389 | RDP | TPKT 连接请求 |
| 9200 | Elasticsearch | `GET /` 请求 |
| 25/587 | SMTP | `HELO` 命令 |

内置 **60+ 高危端口库**：Redis 未授权、Docker API、EternalBlue (445)、Elasticsearch RCE 等。

---

## 弱口令爆破

自动对 **SSH (22)**、**MySQL (3306)**、**MSSQL (1433)** 进行弱口令爆破。

| 协议 | 实现方式 |
|------|---------|
| SSH | paramiko 库（推荐）/ plink / sshpass |
| MySQL | 纯 socket 实现 `mysql_native_password` |
| MSSQL | 纯 socket 实现 TDS PRELOGIN + LOGIN7 |

内置 **133 条**常用弱口令字典（`password_dict.txt`），支持 `--dict` 自定义。

---

## 报告导出

支持三种格式，输出到 `./reports/` 目录。

| 格式 | 特点 |
|------|------|
| **JSON** | 完整结构化数据：端口列表、Banner、指纹、爆破结果 |
| **CSV** | 表格格式，16 列字段 |
| **HTML** | 深色主题可视化：统计卡片、端口 Top20 柱状图、服务分布、可折叠详情表 |

---

## TTL 与操作系统猜测

| TTL 范围 | 猜测操作系统 |
|----------|-------------|
| ≤ 32 | 路由器 / 嵌入式设备 |
| 33 - 64 | Linux / Unix / macOS |
| 65 - 128 | Windows |
| 129 - 255 | Cisco / Solaris / 网络设备 |

---

## 项目结构

```
端口扫描/
├── main.py                # 主程序 (命令行 + 交互模式入口)
├── password_dict.txt      # 密码字典 (133条)
├── requirements.txt       # Python 依赖清单
├── .gitignore
├── reports/               # 报告输出目录
│   ├── scan_xxx.json
│   ├── scan_xxx.csv
│   └── scan_xxx.html
└── libs/                  # 第三方依赖库 (需 pip install -r requirements.txt)
```

---

## 依赖说明

| 依赖 | 说明 | 是否必需 |
|------|------|---------|
| Python 3.6+ | 运行环境 | 必需 |
| impacket ≥ 0.13.1 | SMBv2 协议 / DCERPC 服务管理（后渗透 Shell） | 必需 |
| pyasn1 ≥ 0.6.0 | ASN.1 编解码（impacket 依赖） | 必需 |
| pycryptodome ≥ 3.20.0 | 加密算法（NTLM 认证） | 必需 |
| paramiko | SSH 爆破加速 | 可选 |

```bash
pip install -r requirements.txt
pip install paramiko        # 可选，SSH 爆破推荐
```

---

## 打包为 EXE

```bash
pip install pyinstaller

# 单文件 EXE（带控制台）
pyinstaller --onefile --name="端口扫描器" --add-data="password_dict.txt;." main.py
```

---

## License

[MIT License](LICENSE)

仅供学习和合法授权测试使用。
