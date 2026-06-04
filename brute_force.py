
#!/usr/bin/env python3
"""
弱口令爆破模块 - 全网段端口扫描器

包含: SSH / MySQL / MSSQL 弱口令爆破函数 + 自动爆破调度器
"""
import os
import socket
import struct
import time
import threading
import hashlib
import platform
import subprocess as sp
from typing import Optional, List, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import BRUTE_SERVICE_MAP, DICT_PATH, DEFAULT_USERNAMES, _HAS_PARAMIKO
from core import HostInfo, ScanResult, BruteResult


# ============================================================================
# 密码字典加载
# ============================================================================

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


# ============================================================================
# MySQL 原生socket爆破
# ============================================================================

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


# ============================================================================
# MSSQL TDS 原生socket爆破
# ============================================================================

def _mssql_build_prelogin() -> bytes:
    data = bytearray()
    data.append(0x12)  # PRELOGIN type
    data.append(0x01)  # status
    data.extend(struct.pack(">H", 0x002A))  # length
    data.extend(struct.pack(">H", 0x0000))  # spid
    data.append(0x01)  # packet_id
    data.append(0x00)  # window
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


# ============================================================================
# SSH 爆破
# ============================================================================

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

if _HAS_PARAMIKO:
    import paramiko


# ============================================================================
# FTP 爆破 (纯socket)
# ============================================================================

def brute_ftp(host: str, port: int, username: str, password: str,
              timeout: float = 5.0) -> bool:
    """FTP 弱口令爆破 - 单次尝试"""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # 读取欢迎banner
        data = sock.recv(1024)
        if not data or not data.startswith(b"220"):
            return False

        # 发送 USER
        sock.sendall(f"USER {username}\r\n".encode())
        data = sock.recv(1024)
        if not data or b"331" not in data[:3] and b"230" not in data[:3]:
            # 230 = already logged in (anonymous), 331 = need password
            return False

        # 如果已经是230 (anonymous直接登录), 尝试PASS看是否保持登录
        if b"230" in data[:3]:
            return True

        # 发送 PASS
        sock.sendall(f"PASS {password}\r\n".encode())
        data = sock.recv(1024)
        if data and b"230" in data[:3]:
            # 发送 QUIT
            try:
                sock.sendall(b"QUIT\r\n")
            except Exception:
                pass
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


# ============================================================================
# Telnet 爆破 (纯socket)
# ============================================================================

def brute_telnet(host: str, port: int, username: str, password: str,
                 timeout: float = 5.0) -> bool:
    """Telnet 弱口令爆破 - 单次尝试"""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # 等待登录提示 (login/username)
        data = b""
        start = time.time()
        while time.time() - start < timeout:
            try:
                chunk = sock.recv(1024)
                if chunk:
                    data += chunk
                    # 检查是否出现登录提示
                    text_lower = data.lower()
                    if any(kw in text_lower for kw in
                           [b"login:", b"username:", b"user:", b"ogin:"]):
                        break
                else:
                    return False
            except socket.timeout:
                break

        # 发送用户名
        sock.sendall((username + "\r\n").encode())
        time.sleep(0.5)

        # 等待密码提示
        data2 = b""
        start = time.time()
        while time.time() - start < timeout:
            try:
                chunk = sock.recv(1024)
                if chunk:
                    data2 += chunk
                    if b"assword:" in data2.lower():
                        break
                else:
                    return False
            except socket.timeout:
                break

        # 发送密码
        sock.sendall((password + "\r\n").encode())
        time.sleep(1.0)

        # 检查登录结果 - 收集后续输出
        result_data = b""
        start = time.time()
        while time.time() - start < timeout:
            try:
                chunk = sock.recv(4096)
                if chunk:
                    result_data += chunk
                    result_lower = result_data.lower()
                    # 失败标志
                    if any(kw in result_lower for kw in
                           [b"incorrect", b"invalid", b"denied", b"failed",
                            b"login incorrect", b"access denied", b"wrong"]):
                        return False
                    # 成功标志 (出现shell提示符)
                    if any(kw in result_lower for kw in [b"# ", b"$ ", b"> ", b"#\r", b"$\r"]):
                        return True
                    if len(result_data) > 4096:
                        break
                else:
                    break
            except socket.timeout:
                break

        # 如果没有明确失败标志, 且连接仍活跃, 视为可能成功
        if result_data and not any(kw in result_data.lower() for kw in
                                    [b"incorrect", b"invalid", b"denied"]):
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


# ============================================================================
# RDP 爆破 (NLA / NTLM 认证)
# ============================================================================

def brute_rdp(host: str, port: int, username: str, password: str,
              timeout: float = 5.0) -> bool:
    """RDP 弱口令爆破 - 通过 NLA (CredSSP/NTLM) 认证检测

    策略: 发送 RDP Connection Request + NTLMSSP Negotiate,
    从服务器Challenge中解析, 判断认证是否被接受。
    不建立完整RDP会话, 仅检测认证阶段。
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Step 1: RDP Connection Request (TPKT + X.224 + RDP Negotiation)
        rdp_conn = (
            b"\x03\x00\x00\x13"          # TPKT header
            b"\x0e\xe0\x00\x00"          # X.224
            b"\x00\x00\x00\x01\x00\x08"  # RDP Negotiation
            b"\x00\x03\x00\x00\x00"      # RDP Negotiation Request (NLA + TLS + RDP)
        )
        sock.sendall(rdp_conn)

        data = b""
        try:
            while len(data) < 4096:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass

        if len(data) < 11 or data[:2] != b"\x03\x00":
            return False

        # 解析TPKT长度
        tpkt_len = struct.unpack(">H", data[2:4])[0]
        if tpkt_len < 11 or tpkt_len > len(data) + 4:
            return False

        # 检查是否选择了NLA (type=1)
        rdp_nego = data[11:tpkt_len] if tpkt_len <= len(data) else data[11:]
        if len(rdp_nego) < 8:
            return False
        nego_type = rdp_nego[0]
        if nego_type != 2:  # 0x02 = TYPE_RDP_NEG_RSP
            return False
        selected_proto = struct.unpack("<I", rdp_nego[4:8])[0]
        if not (selected_proto & 0x02):  # NLA not selected
            return False

        # Step 2: 发送 NTLMSSP Negotiate (Type 1) via CredSSP/TSRequest
        ntlm_nego = bytes([
            0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,  # "NTLMSSP\0"
            0x01, 0x00, 0x00, 0x00,  # Type 1
            0x07, 0x82, 0x08, 0xa2,  # Flags
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Domain
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Workstation
        ])

        # 构造 CredSSP TSRequest 包装 NTLM 数据
        # ASN.1 DER 编码简化版本
        nego_token = _wrap_ts_request(ntlm_nego)

        # 通过 TPKT 发送
        tpkt_header = b"\x03\x00" + struct.pack(">H", len(nego_token) + 4)
        sock.sendall(tpkt_header + nego_token)

        # Step 3: 接收 NTLMSSP Challenge (Type 2)
        data2 = b""
        try:
            while len(data2) < 8192:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                data2 += chunk
                if b"NTLMSSP" in data2:
                    break
        except socket.timeout:
            pass

        if b"NTLMSSP" not in data2:
            return False

        # 提取 server challenge
        ntlm_idx = data2.find(b"NTLMSSP")
        if ntlm_idx < 0:
            return False

        # Type 2 message has challenge at byte 24 (after NTLMSSP\0\2)
        challenge_start = ntlm_idx + 24
        if challenge_start + 8 > len(data2):
            return False
        server_challenge = data2[challenge_start:challenge_start + 8]

        # Step 4: 构造 NTLMSSP Authenticate (Type 3)
        nt_hash = hashlib.new('md4', password.encode('utf-16-le')).digest()

        # NTLMv2 Response
        client_challenge = os.urandom(8)
        # Build blob
        timestamp_raw = struct.pack("<q", 0)
        blob = (
            b"\x01\x01\x00\x00"           # RespType + HiRespType
            + b"\x00\x00\x00\x00"         # Reserved
            + timestamp_raw               # Timestamp
            + client_challenge            # ClientChallenge
            + b"\x00\x00\x00\x00"         # Reserved
            + b"\x02\x00\x0c\x00"         # target info
            + b"\x00\x00\x00\x00"         # terminator
        )
        # HMAC-MD5 of challenge + blob
        response_key = hashlib.new('md4', nt_hash).digest()  # NTLMv2 hash
        hmac_input = server_challenge + blob
        ntproof = _hmac_md5(response_key, hmac_input)
        ntlmv2_response = ntproof + blob

        # LM Response (empty for NTLMv2)
        lm_response = b"\x00" * 24

        # Build Type 3 message
        domain = b""
        user = username.encode('utf-16-le')
        hostname = socket.gethostname().encode('utf-16-le')

        # Calculate offsets
        lm_offset = 64
        nt_offset = lm_offset + len(lm_response)
        domain_offset_src = nt_offset + len(ntlmv2_response)
        user_offset = domain_offset_src + len(domain)
        host_offset = user_offset + len(user)

        # Pad to alignment
        while domain_offset_src % 2 != 0:
            domain_offset_src += 1

        msg_len = host_offset + len(hostname)

        type3 = bytearray(64)
        type3[0:8] = b"NTLMSSP\x00"  # Signature
        struct.pack_into("<I", type3, 8, 3)  # Type 3

        # LM Response
        struct.pack_into("<HH", type3, 12, len(lm_response), len(lm_response))
        struct.pack_into("<I", type3, 16, lm_offset)

        # NT Response
        struct.pack_into("<HH", type3, 20, len(ntlmv2_response), len(ntlmv2_response))
        struct.pack_into("<I", type3, 24, nt_offset)

        # Domain
        struct.pack_into("<HH", type3, 28, len(domain), len(domain))
        struct.pack_into("<I", type3, 32, domain_offset_src)

        # User
        struct.pack_into("<HH", type3, 36, len(user), len(user))
        struct.pack_into("<I", type3, 40, user_offset)

        # Host
        struct.pack_into("<HH", type3, 44, len(hostname), len(hostname))
        struct.pack_into("<I", type3, 48, host_offset)

        # Session Key
        struct.pack_into("<I", type3, 52, 0)
        struct.pack_into("<I", type3, 56, 0)

        # Flags
        struct.pack_into("<I", type3, 60, 0x00088205)

        # Append data
        payload = b""
        payload += lm_response
        payload += ntlmv2_response
        payload += domain
        payload += user
        payload += hostname

        full_type3 = bytes(type3) + payload

        # Wrap in TSRequest
        auth_request = _wrap_ts_request(full_type3)
        tpkt_header3 = b"\x03\x00" + struct.pack(">H", len(auth_request) + 4)
        sock.sendall(tpkt_header3 + auth_request)

        # Step 5: 接收认证结果
        data3 = b""
        try:
            while len(data3) < 8192:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                data3 += chunk
                if len(data3) > 4096:
                    break
        except socket.timeout:
            pass

        # 检查是否认证成功
        # 成功: 收到更多数据 (RDP连接继续) 或 没有收到ACCESS_DENIED
        # 失败: 通常服务器会断开连接 或 返回错误
        if len(data3) > 100:
            # 检查是否有错误标志
            if b"NTLMSSP" not in data3 and b"\x03\x00" in data3[:4]:
                # 继续收到TPKT数据, 很可能认证成功
                return True
            # 如果有后续NTLM消息, 可能是错误
            if data3.find(b"NTLMSSP") > 0:
                return False

        # 如果服务器没有立即断开, 且我们收到了有效响应
        return len(data3) > 50

    except Exception:
        return False
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _hmac_md5(key: bytes, msg: bytes) -> bytes:
    """HMAC-MD5 实现"""
    block_size = 64
    if len(key) > block_size:
        key = hashlib.new('md5', key).digest()
    key = key.ljust(block_size, b'\x00')
    o_key_pad = bytes(k ^ 0x5c for k in key)
    i_key_pad = bytes(k ^ 0x36 for k in key)
    return hashlib.new('md5', o_key_pad + hashlib.new('md5', i_key_pad + msg).digest()).digest()


def _wrap_ts_request(ntlm_data: bytes) -> bytes:
    """将 NTLM 数据包装为 CredSSP TSRequest (简化ASN.1 DER)"""
    nego_tokens_field = (
        bytes([0xa1]) + _asn1_len(len(ntlm_data) + 2 + 2) +
        bytes([0x30]) + _asn1_len(len(ntlm_data) + 2) +
        bytes([0xa0]) + _asn1_len(len(ntlm_data)) +
        bytes([0x04]) + _asn1_len(len(ntlm_data)) +
        ntlm_data
    )
    ts_request = (
        bytes([0x30]) + _asn1_len(len(nego_tokens_field) + 2) +
        bytes([0xa0]) + _asn1_len(len(nego_tokens_field)) +
        nego_tokens_field
    )
    return ts_request


def _asn1_len(length: int) -> bytes:
    """ASN.1 DER 长度编码"""
    if length < 0x80:
        return bytes([length])
    if length < 0x100:
        return bytes([0x81, length])
    return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


# ============================================================================
# PostgreSQL 爆破 (纯socket, MD5认证)
# ============================================================================

def _pg_build_startup(user: str, database: str = "postgres") -> bytes:
    """构造 PostgreSQL StartupMessage"""
    payload = struct.pack(">I", 0x00030000)  # protocol 3.0
    for key, val in [("user", user), ("database", database), ("client_encoding", "UTF8")]:
        payload += key.encode() + b"\x00" + val.encode() + b"\x00"
    payload += b"\x00"  # terminator
    header = struct.pack(">I", len(payload) + 4)
    return header + payload


def _pg_read_message(sock: socket.socket, timeout: float = 3.0) -> Optional[Tuple[int, bytes]]:
    """读取PostgreSQL消息, 返回 (msg_type, payload)"""
    try:
        type_byte = sock.recv(1)
        if not type_byte:
            return None
        length_bytes = sock.recv(4)
        if len(length_bytes) < 4:
            return None
        msg_len = struct.unpack(">I", length_bytes)[0] - 4
        payload = b""
        while len(payload) < msg_len:
            chunk = sock.recv(msg_len - len(payload))
            if not chunk:
                break
            payload += chunk
        return (type_byte[0], payload)
    except Exception:
        return None


def brute_postgresql(host: str, port: int, username: str, password: str,
                     timeout: float = 5.0) -> bool:
    """PostgreSQL 弱口令爆破 (MD5认证) - 单次尝试"""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Step 1: 发送 StartupMessage
        startup = _pg_build_startup(username)
        sock.sendall(startup)

        # Step 2: 读取 Authentication Request
        auth_msg = _pg_read_message(sock, timeout)
        if not auth_msg:
            return False

        msg_type, payload = auth_msg

        if msg_type == ord('R'):
            auth_type = struct.unpack(">I", payload[:4])[0]

            if auth_type == 0:  # AuthenticationOk
                return True

            if auth_type == 5:  # MD5 password
                salt = payload[4:8]

                # MD5(MD5(password + user) + salt)
                inner = hashlib.md5((password + username).encode()).hexdigest()
                outer_input = inner.encode() + salt
                auth_hash = "md5" + hashlib.md5(outer_input).hexdigest()

                # 发送 PasswordMessage
                pw_msg = b"p" + struct.pack(">I", len(auth_hash) + 5) + auth_hash.encode() + b"\x00"
                sock.sendall(pw_msg)

                # Step 3: 读取认证结果
                result_msg = _pg_read_message(sock, timeout)
                if result_msg:
                    rtype, _ = result_msg
                    # AuthenticationOk (R type 0) or ReadyForQuery (Z)
                    if rtype == ord('R'):
                        if len(_) >= 4:
                            result_auth = struct.unpack(">I", _[:4])[0]
                            return result_auth == 0
                    # Some servers send ReadyForQuery directly after auth ok
                    if rtype == ord('Z'):
                        return True
                    # ErrorResponse
                    if rtype == ord('E'):
                        return False
                return False
        elif msg_type == ord('E'):  # Error
            return False

        return False
    except Exception:
        return False
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# ============================================================================
# 爆破调度
# ============================================================================

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
            "FTP": brute_ftp,
            "SSH": brute_ssh,
            "Telnet": brute_telnet,
            "MySQL": brute_mysql,
            "MSSQL": brute_mssql,
            "RDP": brute_rdp,
            "PostgreSQL": brute_postgresql,
        }
        brute_func = brute_func_map.get(service_name)
        if not brute_func:
            continue

        if service_name == "SSH" and not _HAS_PARAMIKO:
            print(f"  [!] 未安装 paramiko, SSH爆破将使用 subprocess 方案(效率较低)")
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
