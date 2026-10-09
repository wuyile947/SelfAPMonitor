"""热点侧过滤 DNS 服务 (域名拦截 / 设备级断网).

原理 (已实测验证): Windows 热点客户端的 DNS 查询直接发往网关 (如 192.168.137.1:53),
由 ICS 的通配 0.0.0.0:53 代理解析. UDP 特定绑定 AP_IP:53 可与 ICS 通配绑定共存
并优先收到客户端查询:

  - 源IP 在 blocked_ips (设备断网名单)    -> 所有域名返回 0.0.0.0 / NODATA
  - 命中黑名单/短视频关键字/确定广告SDK    -> 返回 0.0.0.0 (解析即拦截)
  - 其余域名                              -> 透明转发给上游 DNS

不再修改主机/适配器的 DNS 设置 (旧版 127.0.0.1 方案已废弃);
AP IP 变化时自动重绑, 热点未开启时每 5 秒轮询等待.
不注入任何数据包, 应答仅为 DNS 协议内的拒绝解析.

注意: 仅对走系统 DNS 的查询有效 (App 内置 HTTPDNS/DoH 绕过).
"""
import json
import socket
import struct
import threading
import time

from . import firewall  # 复用 run_ps (Base64/CREATE_NO_WINDOW 封装)


UPSTREAM_FALLBACK = ["223.5.5.5", "119.29.29.29"]


# ---------- DNS 报文最小实现 ----------

def _parse_question(pkt):
    """解析查询报文的 (txid, qtype, qname, question原始字节). 非查询返回 None."""
    try:
        if len(pkt) < 17:
            return None
        txid = pkt[:2]
        flags = struct.unpack(">H", pkt[2:4])[0]
        if flags & 0x8000:          # QR=1 是应答, 不处理
            return None
        qdcount = struct.unpack(">H", pkt[4:6])[0]
        if qdcount < 1:
            return None
        pos = 12
        labels = []
        while True:
            n = pkt[pos]
            if n == 0:
                pos += 1
                break
            if n & 0xC0:            # 查询里不应出现压缩指针
                return None
            labels.append(pkt[pos + 1:pos + 1 + n].decode("ascii", "replace"))
            pos += 1 + n
        qtype = struct.unpack(">H", pkt[pos:pos + 2])[0]
        question = pkt[12:pos + 4]  # qname + qtype + qclass
        return txid, qtype, ".".join(labels).lower(), question
    except Exception:
        return None


def _reply_blocked(txid, qtype, question, ip="0.0.0.0"):
    """构造拦截应答: A查询返回 ip (默认0.0.0.0; 警告页模式返回网关IP);
    AAAA/HTTPS等其他类型返回空应答(NODATA)."""
    header = txid + struct.pack(">HHHHH", 0x8580, 1, 0 if qtype != 1 else 1, 0, 0)
    if qtype == 1:
        ans = (b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 10, 4)
               + socket.inet_aton(ip))
        return header + question + ans
    return header + question


def _reply_servfail(txid):
    return txid + struct.pack(">HHHHH", 0x8182, 0, 0, 0, 0)


# ---------- 主机 DNS 适配器读取 (仅用于读上游 + 旧版本残留自愈) ----------

_PS_HEAD = ("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n"
            "Import-Module DnsClient -ErrorAction SilentlyContinue\n"
            "Get-DnsClientServerAddress -AddressFamily IPv4 | "
            "Select-Object InterfaceIndex, InterfaceAlias, "
            "InterfaceDescription, ServerAddresses | ConvertTo-Json -Compress")


def _read_adapters():
    """读取全部 IPv4 DNS 适配器 (原始行), 过滤逻辑在 Python 侧做.

    PS 脚本刻意不含脚本块/$_: PowerShell 大括号内表达式跨行会导致解析错误,
    单行管道 + Python 过滤最稳."""
    out, err, _ = firewall.run_ps(_PS_HEAD, timeout=30)
    rows = []
    try:
        data = json.loads(out)
        rows = data if isinstance(data, list) else ([data] if data else [])
    except Exception:
        pass
    result = {}
    for r in rows:
        try:
            servers = r.get("ServerAddresses") or []
            if isinstance(servers, str):   # 单个DNS时 ConvertTo-Json 输出标量
                servers = [servers]
            servers = [str(x) for x in servers if str(x)]
            if not servers:
                continue
            alias = str(r.get("InterfaceAlias") or "").lower()
            desc = str(r.get("InterfaceDescription") or "").lower()
            if "loopback" in alias or "wi-fi direct" in desc:
                continue
            result[int(r["InterfaceIndex"])] = servers
        except Exception:
            continue
    return result


def get_upstreams():
    """读取主机现有 IPv4 DNS 上游 {ifIndex: [servers]}, 供转发与自愈使用."""
    return _read_adapters()


def _set_dns_lines(pairs):
    """生成逐适配器显式设置脚本 (无变量/无脚本块, 每行独立 try/catch)."""
    lines = ["$ErrorActionPreference = 'Stop'",
             "Import-Module DnsClient -ErrorAction SilentlyContinue"]
    for idx, arg in pairs:
        lines.append(f"try {{ Set-DnsClientServerAddress -InterfaceIndex {idx} "
                     f"{arg} -ErrorAction Stop; Write-Output 'OK{idx}' }} "
                     f"catch {{ Write-Output 'ERR{idx}' }}")
    return "\n".join(lines)


def restore_host_dns(orig):
    """旧版本残留自愈: 把仍指向 127.0.0.1 的适配器复位为自动获取.

    旧版方案曾把主机 DNS 指向 127.0.0.1 (强杀进程时无清理路径会卡死主机 DNS);
    新方案不再修改主机 DNS, 本函数仅用于清理历史残留. orig 传空字典即可."""
    pairs = []
    for idx, servers in (orig or {}).items():
        if servers:
            s = ",".join(f"'{x}'" for x in servers)
            pairs.append((idx, f"-ServerAddresses {s}"))
        else:
            pairs.append((idx, "-ResetServerAddresses"))
    if pairs:
        firewall.run_ps(_set_dns_lines(pairs), timeout=60)
    # 兜底: 任何仍指向 127.0.0.1 的适配器 -> 复位为自动获取
    stuck = [(i, "-ResetServerAddresses") for i, v in get_upstreams().items()
             if "127.0.0.1" in v]
    if stuck:
        firewall.run_ps(_set_dns_lines(stuck), timeout=60)


def host_dns_stuck():
    """主机适配器是否残留 127.0.0.1 DNS (旧版本遗留)."""
    try:
        return any("127.0.0.1" in v for v in get_upstreams().values())
    except Exception:
        return False


# ---------- 过滤服务线程 ----------

class DNSFilter(threading.Thread):
    """AP_IP:53 上的过滤 DNS.

    blocked_cb(qname, rule, src_ip) 用于告警/日志;
    ap_ip_fn() 每轮轮询读取当前热点网关 IP (由 control 注入, 内部不加锁);
    set_blocked_ips(ips) 原子更新设备断网名单 (源IP)."""

    def __init__(self, config, blocked_cb=None):
        super().__init__(daemon=True, name="DNSFilter")
        self.config = config
        self.blocked_cb = blocked_cb        # fn(qname, rule, src_ip)
        self.upstreams = []                 # 转发上游 (enable 时注入)
        self.ap_ip_fn = None                # fn() -> 当前AP网关IP
        self.blocked_ips = set()            # 设备断网名单 (源IP)
        self.portal_ips = set()             # 弹出指定页面设备 (所有查询劫持到网关)
        self.warn_ip_fn = None              # fn() -> 警告页网关IP (None/空=0.0.0.0)
        self._ip_lock = threading.Lock()
        self._sock = None
        self._bound_ip = ""
        self._stop = threading.Event()

    # ---- 对外接口 ----
    def set_blocked_ips(self, ips):
        with self._ip_lock:
            self.blocked_ips = set(ips or [])

    def set_portal_ips(self, ips):
        """弹出指定页面设备: 所有域名解析到网关 (captive portal 301 跳转)."""
        with self._ip_lock:
            self.portal_ips = set(ips or [])

    @property
    def bound_ip(self):
        return self._bound_ip

    def stop(self):
        self._stop.set()
        self._close_sock()

    def _close_sock(self):
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
        self._sock = None

    # ---- 主循环: 热点未开则等待; AP IP 变化则重绑 ----
    def run(self):
        while not self._stop.is_set():
            ap_ip = ""
            try:
                ap_ip = str((self.ap_ip_fn or (lambda: ""))() or "")
            except Exception:
                ap_ip = ""
            if not ap_ip:
                self._close_sock()          # 热点关闭 -> 网卡销毁, 绑定失效
                self._bound_ip = ""
                self._stop.wait(5.0)
                continue
            if ap_ip != self._bound_ip or not self._sock:
                self._close_sock()
                self._bound_ip = ""
                try:
                    self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    self._sock.bind((ap_ip, 53))
                    self._sock.settimeout(1.0)
                    self._bound_ip = ap_ip
                except Exception:
                    self._close_sock()
                    self._stop.wait(5.0)
                    continue
            try:
                pkt, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except Exception:
                self._close_sock()
                self._bound_ip = ""
                self._stop.wait(1.0)
                continue
            threading.Thread(target=self._handle, args=(pkt, addr),
                             daemon=True).start()
        self._close_sock()

    # ---- 单个查询处理 ----
    def _handle(self, pkt, addr):
        p = _parse_question(pkt)
        if not p:
            return
        txid, qtype, qname, question = p
        src_ip = addr[0]
        with self._ip_lock:
            device_blocked = src_ip in self.blocked_ips
        portal = src_ip in self.portal_ips
        hit = None
        if portal:
            hit = "弹页劫持"
        elif device_blocked:
            hit = "设备断网"
        else:
            blk = self.config.match_domain_blacklist(qname)
            if blk:
                hit = blk
            else:
                ad = self.config.match_ad_sdk(qname)
                if ad and ad[0] == "definite":
                    hit = ad[1]
        if hit:
            # 弹页/警告页模式: A 记录应答劫持到网关IP:80 (301跳转/提示页)
            ip = "0.0.0.0"
            if (portal or device_blocked) and self.warn_ip_fn:
                try:
                    ip = str(self.warn_ip_fn() or "") or "0.0.0.0"
                except Exception:
                    ip = "0.0.0.0"
            try:
                self._sock.sendto(_reply_blocked(txid, qtype, question, ip), addr)
            except Exception:
                return
            if self.blocked_cb:
                try:
                    self.blocked_cb(qname, hit, src_ip)
                except Exception:
                    pass
            return
        # 未命中 -> 透明转发
        data = self._forward(pkt)
        try:
            if data:
                self._sock.sendto(data, addr)
            else:
                self._sock.sendto(_reply_servfail(txid), addr)
        except Exception:
            pass

    def _forward(self, pkt):
        for up in (self.upstreams or UPSTREAM_FALLBACK):
            s = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(3.0)
                s.sendto(pkt, (up, 53))
                data, _ = s.recvfrom(4096)
                return data
            except Exception:
                continue
            finally:
                try:
                    if s:
                        s.close()
                except Exception:
                    pass
        return None
