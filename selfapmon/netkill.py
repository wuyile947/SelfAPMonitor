"""连接层主动阻断器 (TCP RST / QUIC Version Negotiation 注入).

背景: DNS 过滤层只能拦截走系统 DNS 的查询; 抖音/快手等 App 内置 HTTPDNS
(向硬编码 IP 直接发 HTTP 请求获取解析结果) 可绕过 DNS 层. 但无论 IP 从何
而来, 业务连接仍会暴露目标域名:
  - TLS ClientHello 的 SNI (TCP 443)
  - HTTP 请求的 Host/URI (TCP 80)
  - QUIC Initial 内的 ClientHello SNI (UDP 443; Initial 包用公开算法加密,
    任何人可解, 属协议规范设计而非破解)

本模块在嗅探到上述连接命中 黑名单/短视频 规则时, 注入协议内合法的
连接终止报文:
  - TCP : 伪造服务端 RST (seq 取自客户端自己宣告的接收序号, 必被接受)
  - QUIC: 伪造 Version Negotiation (只列客户端不可能支持的保留版本号,
          RFC 9000 要求客户端必须放弃本次连接尝试)

效果: HTTPDNS 拿到真实 IP 也没用, 视频/API 连接建立即被掐断;
App 回退到 TCP 后仍被 RST, 业务持续失败.

合规边界 (用户已明确允许主动发包):
  - 仅对自家热点内客户端的连接注入终止报文, 不触碰互联网侧
  - 仅读取明文握手元数据 (SNI/Host), 不解密任何业务内容, 不做内容级中间人
  - 不伪造业务数据, 仅发送协议标准定义的连接终止报文 (RST / VN)
"""
import os
import queue
import threading
import time
from collections import deque

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    CRYPTO_OK = True
except Exception:
    CRYPTO_OK = False

try:
    from scapy.all import Ether, IP, TCP, UDP, Raw, sendp
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False


# QUIC Initial 密钥盐: v1 (RFC 9001) / draft-29 / v2 (RFC 9369)
_QUIC_SALTS = {
    0x00000001: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    0xff00001d: bytes.fromhex("afbfcf7033090033fffcd3cd77f21b51a2b3df0e"),
    0x6b3343cf: bytes.fromhex("0bede15b58b0e34c7f20439b85a71c2a4e85ee5c"),
}


def _varint(buf, off):
    """QUIC 可变长整数. 返回 (值, 新偏移); 解析失败返回 (None, off)."""
    try:
        b0 = buf[off]
    except IndexError:
        return None, off
    prefix = b0 >> 6
    if prefix == 0:
        return b0, off + 1
    if prefix == 1:
        return ((b0 & 0x3F) << 8) | buf[off + 1], off + 2
    if prefix == 2:
        return (((b0 & 0x3F) << 8 | buf[off + 1]) << 8 | buf[off + 2]), off + 3
    v = 0
    for i in range(8):
        v = (v << 8) | buf[off + i]
    return v, off + 8


def _expand_label(secret, label, length):
    full = b"tls13 " + label
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + b"\x00"
    return HKDF(algorithm=hashes.SHA256(), length=length,
                salt=secret, info=info).derive(b"")


def _crypto_frames(data):
    """从 Initial 解密后的帧区提取 CRYPTO 帧 {offset: bytes}."""
    out = {}
    i = 0
    n = len(data)
    while i < n:
        t = data[i]
        if t == 0x00:            # PADDING
            i += 1
            continue
        if t == 0x01:            # PING
            i += 1
            continue
        if t == 0x06:            # CRYPTO
            off, i = _varint(data, i + 1)
            ln, i = _varint(data, i)
            if off is None or ln is None or i + ln > n:
                return out
            out[off] = data[i:i + ln]
            i += ln
            continue
        return out               # ACK/其他帧 -> 停止 (客户端 Initial 少见)
    return out


def quic_initial_sni(payload):
    """解析 QUIC v1/draft-29 客户端 Initial, 解出 (sni, client_scid).

    Initial 使用由 DCID 派生的公开密钥加密 (RFC 9001), 仅解出 ClientHello
    的 SNI 明文, 不涉及任何会话业务数据. 失败返回 None."""
    if not CRYPTO_OK or not payload or len(payload) < 40:
        return None
    try:
        if not (payload[0] & 0x80):                     # 非长头部
            return None
        version = int.from_bytes(payload[1:5], "big")
        salt = _QUIC_SALTS.get(version)
        if salt is None:                                # 不支持的版本
            return None
        dcid_len = payload[5]
        dcid = payload[6:6 + dcid_len]
        pos = 6 + dcid_len
        scid_len = payload[pos]
        scid = payload[pos + 1:pos + 1 + scid_len]
        pos += 1 + scid_len
        token_len, pos = _varint(payload, pos)
        if token_len is None:
            return None
        pos += token_len
        length, pos = _varint(payload, pos)             # 覆盖 pn+payload
        if length is None or length <= 4:
            return None
        pn_off = pos
        if len(payload) < pn_off + 4 + 16:              # hp 采样不足
            return None
        # ---- 密钥派生 (公开算法) ----
        initial_secret = HKDF(algorithm=hashes.SHA256(), length=32,
                              salt=salt, info=b"").derive(dcid)
        c_secret = _expand_label(initial_secret, b"client in", 32)
        key = _expand_label(c_secret, b"quic key", 16)
        iv = _expand_label(c_secret, b"quic iv", 12)
        hp = _expand_label(c_secret, b"quic hp", 16)
        # ---- 去头部保护 ----
        sample = payload[pn_off + 4:pn_off + 20]
        enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
        mask = enc.update(sample) + enc.finalize()
        b0u = payload[0] ^ (mask[0] & 0x0F)             # 长头部低4位
        pn_len = (b0u & 0x03) + 1
        pn_bytes = bytes(payload[pn_off + i] ^ mask[1 + i] for i in range(pn_len))
        pn = int.from_bytes(pn_bytes, "big")
        if pn_off + pn_len + 16 > len(payload):
            return None
        # AAD = 去保护后的头部 (含恢复出的 Packet Number 字节)
        aad = bytes([b0u]) + payload[1:pn_off] + pn_bytes
        nonce = bytes(a ^ b for a, b in zip(
            iv, pn.to_bytes(12, "big")))
        # 线上布局: 头部 || pn(明文,hp保护) || 密文(含16字节GCM tag);
        # Length 覆盖 pn+密文+tag, AEAD 明文只有帧
        ct = payload[pn_off + pn_len:pn_off + length]
        pt = AESGCM(key).decrypt(nonce, ct, aad)
        crypto = _crypto_frames(pt)
        if not crypto:
            return None
        ch = b"".join(crypto[k] for k in sorted(crypto))
        if len(ch) < 4 or ch[0] != 0x01:                # 非 ClientHello
            return None
        # 包一层 TLS record 头, 复用现有解析器
        from .tls_meta import parse_tls_client_hello
        rec = b"\x16\x03\x01" + len(ch).to_bytes(2, "big") + ch
        tls = parse_tls_client_hello(rec)
        if not tls or not tls.get("sni"):
            return None
        return tls["sni"], scid
    except Exception:
        return None


def quic_header_scid(payload):
    """仅解析长头部明文字段 (不解密): 返回 (version, scid) 供 VN 构造.

    VN 报文不加密, 只需回显客户端 SCID, 因此即使 Initial 解密失败
    (未知版本等), 对已断网设备仍可发 VN 拒绝. 失败返回 None."""
    if not payload or len(payload) < 7 or not (payload[0] & 0x80):
        return None
    version = int.from_bytes(payload[1:5], "big")
    if version == 0:                        # Version Negotiation 包本身
        return None
    try:
        dcid_len = payload[5]
        pos = 6 + dcid_len
        if pos >= len(payload):
            return None
        scid_len = payload[pos]
        pos += 1
        if pos + scid_len > len(payload):
            return None
        return version, payload[pos:pos + scid_len]
    except Exception:
        return None


def build_quic_vn(client_scid):
    """构造 Version Negotiation 报文 (只列保留版本 -> 客户端必须放弃)."""
    dcid = bytes(client_scid or b"")
    scid = os.urandom(8)
    first = 0xC0 | (os.urandom(1)[0] & 0x03)            # long+fixed+随机位
    return (bytes([first])
            + b"\x00\x00\x00\x00"                       # version 0
            + bytes([len(dcid)]) + dcid                 # 回显客户端 SCID
            + bytes([len(scid)]) + scid
            + b"\x0a\x0a\x0a\x0a\x1a\x2a\x3a\x4a")      # 保留版本 -> 必须拒绝


def http_request_domains(data):
    """从 HTTP 请求中提取候选域名 (Host 头 / 绝对URI / dn= 参数等)."""
    out = []
    try:
        text = data[:1600].decode("utf-8", "replace")
        line = text.split("\r\n", 1)[0]
        parts = line.split(" ")
        if len(parts) >= 2 and parts[0] in ("GET", "POST", "PUT", "HEAD",
                                            "OPTIONS", "DELETE"):
            uri = parts[1]
            if uri.startswith("http://") or uri.startswith("https://"):
                host = uri.split("//", 1)[1].split("/", 1)[0]
                out.append(host.split("@")[-1])
            for key in ("dn=", "domain=", "host=", "name="):
                idx = uri.lower().find(key)
                if idx >= 0:
                    val = uri[idx + len(key):].split("&", 1)[0]
                    if "." in val:
                        out.append(val)
        for h in text.split("\r\n")[1:20]:
            if h.lower().startswith("host:"):
                out.append(h.split(":", 1)[1].strip())
                break
    except Exception:
        pass
    return [d.strip().lower().rstrip(".") for d in out
            if d and "." in d and " " not in d]


class NetKiller(threading.Thread):
    """连接终止注入器 (嗅探解析线程 -> 提交动作 -> 本线程发送).

    iface_fn() 返回 Scapy 热点网卡对象 (与嗅探同一网卡, 直接 L2 发给客户端);
    kill_cb(kind, domain, rule, it) 用于日志 (control 注入);
    err_cb(tag, count, it) 用于发送/解析失败诊断 (control 注入, 60秒节流).

    blocked_ips: 已断网/踢除设备的源IP集合 -> 其所有 TCP 连接 RST、
    所有 QUIC Initial 拒绝 (不限域名), 补齐 HTTPDNS 绕过 DNS 层的缺口."""

    def __init__(self, config, iface_fn, kill_cb=None, err_cb=None):
        super().__init__(daemon=True, name="NetKill")
        self.config = config
        self.iface_fn = iface_fn
        self.kill_cb = kill_cb
        self.err_cb = err_cb
        self._q = queue.Queue(maxsize=800)
        self._seen = {}                     # (kind,src,dst,sport,dport) -> ts
        self._sent = deque(maxlen=256)      # RST 速率窗口 (VN 不限速, 见 _fire)
        self._stop_ev = threading.Event()
        self._blk_ips = set()               # 断网设备IP (set_blocked_ips 更新)
        self._blk_macs = set()              # 断网设备MAC (重连换IP零窗口期)
        self._diag = {}                     # tag -> 累计次数
        self._diag_ts = {}                  # tag -> 上次上报时间 (60秒节流)

    # ---- 断网设备名单 (control._sync_blocked 推送) ----
    def set_blocked_ips(self, ips):
        self._blk_ips = set(ips or ())

    def set_blocked_macs(self, macs):
        """MAC 名单: 嗅探包自带 src_mac, 设备重连换IP的窗口期也能立即杀."""
        self._blk_macs = {str(m).replace(":", "").replace("-", "").lower()
                          for m in (macs or ())}

    def is_blocked_ip(self, ip):
        return ip in self._blk_ips

    def is_blocked(self, it):
        """按 IP 或 MAC 判定断网设备 (MAC 归一化比较, 无窗口期)."""
        if it.get("src") in self._blk_ips:
            return True
        mac = str(it.get("src_mac") or "").replace(":", "").replace("-", "").lower()
        return bool(mac) and mac in self._blk_macs

    def has_blocked(self):
        return bool(self._blk_ips or self._blk_macs)

    # ---- 对外入口 (嗅探解析线程调用, 必须快) ----
    def on_tls(self, it, sni):
        if not (sni and it.get("direction") == "up"):
            return
        hit = ("设备断网" if self.is_blocked(it)
               else self.config.match_domain_blacklist(sni))
        if hit:
            self._submit(("rst",), it, hit, sni)

    def on_http(self, it):
        if it.get("direction") != "up":
            return
        if self.is_blocked(it):             # 断网设备: HTTPDNS请求本身也掐断
            self._submit(("rst",), it, "设备断网", "(全部HTTP连接)")
            return
        for d in http_request_domains(it.get("http") or b""):
            hit = self.config.match_domain_blacklist(d)
            if hit:
                self._submit(("rst",), it, hit, d)
                return

    def on_quic(self, it):
        q = it.get("quic") or b""
        blocked = self.is_blocked(it)
        if blocked:
            self._diag_note("quic_seen_blocked", it)   # 打点: 到达率排查
        info = quic_initial_sni(q)
        if info:
            sni, scid = info
            hit = ("设备断网" if blocked
                   else self.config.match_domain_blacklist(sni))
            if hit:
                self._submit(("vn", scid), it, hit, sni)
            return
        if blocked:
            # 解密失败(未知版本等)也拒绝: VN 不加密, 只需回显明文头部 SCID
            hdr = quic_header_scid(q)
            if hdr:
                self._submit(("vn", hdr[1]), it, "设备断网(QUIC)",
                             f"ver:{hdr[0]:08x}")
        else:
            self._diag_note("quic_decrypt_fail", it)   # 诊断: QUIC零命中排查

    def on_tcp_any(self, it):
        """断网设备兜底: 任意上行 TCP 包 (含非443/80端口) 直接 RST."""
        if (it.get("direction") == "up" and it.get("proto") == 6
                and it.get("tcp_seq") is not None
                and self.is_blocked(it)):
            self._diag_note("tcp_seen_blocked", it)    # 打点: 到达率排查
            self._submit(("rst",), it, "设备断网",
                         f"{it['sport']}->{it['dport']}")

    def _submit(self, action, it, rule, domain):
        key = (action[0], it["src"], it["dst"], it["sport"], it["dport"])
        now = time.time()
        if now - self._seen.get(key, 0) < 45:           # 同流45秒只杀一次
            return
        self._seen[key] = now
        if len(self._seen) > 4096:
            for k in [k for k, v in self._seen.items() if now - v > 300]:
                self._seen.pop(k, None)
        try:
            self._q.put_nowait((action, it, rule, domain))
        except queue.Full:
            pass

    # ---- 诊断上报 (60秒每tag一条) ----
    def _diag_note(self, tag, it=None):
        self._diag[tag] = self._diag.get(tag, 0) + 1
        now = time.time()
        if now - self._diag_ts.get(tag, 0) < 60:
            return
        self._diag_ts[tag] = now
        if self.err_cb:
            try:
                self.err_cb(tag, self._diag[tag], it or {})
            except Exception:
                pass

    # ---- 工作线程 ----
    def run(self):
        while not self._stop_ev.is_set():
            try:
                action, it, rule, domain = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._fire(action, it, rule, domain)
            except Exception as e:
                self._diag_note(f"fire:{type(e).__name__}", it)

    def _fire(self, action, it, rule, domain):
        if not SCAPY_OK:
            self._diag_note("scapy_unavailable", it)
            return
        # 速率保护仅限 RST (≤150包/秒, 超速丢弃无妨——同流45秒后会再触发);
        # VN 不限速不丢弃: QUIC Initial 重传同四元组被 _submit 45秒去重挡住,
        # 丢一次 = 这条 QUIC 连接彻底漏杀 (重连风暴期 RST 会挤死 VN).
        if action[0] == "rst":
            now = time.time()
            if len(self._sent) >= 150 and now - self._sent[0] < 1.0:
                self._diag_note("rate_limited", it)
                return
            self._sent.append(time.time())
        iface = None
        try:
            iface = self.iface_fn()
        except Exception:
            iface = None
        if iface is None:
            self._diag_note("no_send_iface", it)
            return
        dst_mac = it.get("src_mac") or ""               # 客户端MAC (上行包)
        if not dst_mac:
            self._diag_note("no_client_mac", it)
            return
        eth = Ether(src=it.get("dst_mac") or None, dst=dst_mac)
        ip = IP(src=it["dst"], dst=it["src"])
        if action[0] == "rst":
            plen = len(it.get("payload") or b"") + len(it.get("http") or b"")
            tcp = TCP(sport=it["dport"], dport=it["sport"], flags="RA",
                      seq=it.get("tcp_ack") or 0,
                      ack=(it.get("tcp_seq") or 0) + plen, window=0)
            pkt = eth / ip / tcp
        else:                                           # vn
            vn = build_quic_vn(action[1])
            pkt = eth / ip / UDP(sport=it["dport"], dport=it["sport"]) / Raw(vn)
        try:
            sendp(pkt, iface=iface, verbose=0)
        except Exception as e:
            self._diag_note(f"sendp:{type(e).__name__}", it)
            return
        if self.kill_cb:
            try:
                self.kill_cb(action[0], domain, rule, it)
            except Exception:
                pass

    def stop(self):
        self._stop_ev.set()
