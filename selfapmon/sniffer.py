"""Scapy 抓包引擎 (嗅探本身纯被动; 主动发包仅 netkill 的连接终止报文).

只提取元数据:
  - 五元组/包长/方向  -> 速率与流量统计
  - UDP/TCP 53        -> DNS 查询名 (明文DNS); DoT(853) 仅标记"加密DNS"
  - TCP 443 首载荷    -> TLS ClientHello 明文字段 (SNI/ALPN/JA3/ECH标记)
  - TCP 80  首载荷    -> HTTP Host/URI (netkill 连接层阻断用)
  - UDP 443 Initial   -> QUIC ClientHello SNI (netkill 连接层阻断用)

线程模型:
  AsyncSniffer(内核线程) --prn--> 计数 + 入队
  ParseThread(独立线程)  --解析--> 流表/分类/DNS日志/告警 -> storage 队列
"""
import threading
import time
from collections import deque

from . import tls_meta
from .tls_meta import parse_dns, parse_tls_client_hello

try:
    from scapy.all import IP, TCP, UDP, Ether, AsyncSniffer, conf
    SCAPY_OK = True
except Exception:  # scapy 未安装时 GUI 仍可启动(提示安装)
    SCAPY_OK = False


class Flow:
    __slots__ = ("key", "mac", "ip", "raddr", "proto", "sport", "dport",
                 "packets", "bytes_up", "bytes_down", "first_ts", "last_ts",
                 "category", "detail", "sni", "alpn", "ja3", "ech", "esni",
                 "tls_version", "dnstype", "qname", "blocked", "payloads", "ip_bytes")

    def __init__(self, key, mac, ip, raddr, proto, sport, dport, ts):
        self.key = key
        self.mac = mac
        self.ip = ip
        self.raddr = raddr
        self.proto = proto
        self.sport = sport
        self.dport = dport
        self.bytes_up = 0
        self.bytes_down = 0
        self.first_ts = ts
        self.last_ts = ts
        self.category = None
        self.detail = ""
        self.sni = ""
        self.alpn = ""
        self.ja3 = ""
        self.ech = False
        self.esni = False
        self.tls_version = ""
        self.dnstype = ""
        self.qname = ""
        self.blocked = False
        self.payloads = []     # 供 DPI 的 (proto, sport, dport, payload, ip_bytes)
        self.ip_bytes = None


class Sniffer:
    def __init__(self, config, storage, dpi_engine, emit_alert, control_ref=None):
        """
        config: Config
        storage: Storage (线程安全队列)
        dpi_engine: DpiEngine
        emit_alert: fn(kind, mac, msg)  告警回调 (由 alerts 模块节流)
        control_ref: dict  共享引用 {'ap_mac': str, 'ap_iface': {...}} 由监控线程更新
        """
        self.config = config
        self.storage = storage
        self.dpi = dpi_engine
        self.emit_alert = emit_alert
        self.control_ref = control_ref or {}

        self.flows = {}                      # key -> Flow
        self.mac_bytes = {}                  # mac -> {'up': int, 'down': int, 'total': int}
        self.mac_rate = {}                   # mac -> deque[(ts, up_delta, down_delta)]
        self.mac_categories = {}             # mac -> {category: bytes}
        self.dns_seen = {}                   # (mac, qname) -> ts  去重
        self.dns_no_plaintext = {}           # mac -> set(sni 无明文DNS的域名)

        self._lock = threading.Lock()
        self._queue = []                     # 原始包队列 (prn -> parser)
        self._sniffer = None
        self._running = False
        self._user_stopped = False         # 用户手动停止: 看门狗不接管
        self._restarting = False           # 看门狗重启进行中
        self._err = ""
        self._iface_obj = None
        self._pkt_count = 0
        self._last_tick = time.time()
        self._last_pkt_ts = time.time()    # 最后收到包的时间 (看门狗依据)
        self._pps = 0
        self._diag = {"pkt": 0, "udp443": 0, "quic_long": 0}
        self._diag_ts = time.time()        # 60秒打点上报

        self._parser = threading.Thread(target=self._parse_loop, daemon=True, name="PacketParser")
        self._parser.start()

        # 实时活动上报: 解析线程 -> ClientMonitor.note_activity (main.py 接线)
        self.activity_cb = None
        self._act_seen = {}                  # mac -> ts (每MAC 2秒节流)

    # ---------- 生命周期 ----------
    def start(self):
        if self._running:
            return True, "已在运行"
        self._user_stopped = False
        try:
            from scapy.all import AsyncSniffer
        except Exception as e:
            self._err = f"Scapy 不可用: {e}"
            return False, self._err

        iface = self._resolve_iface()
        if iface is None:
            self._err = "未找到热点虚拟网卡 (请先开启热点)"
            return False, self._err
        self._iface_obj = iface
        try:
            self._sniffer = AsyncSniffer(
                iface=iface, filter="ip or arp", store=False, prn=self._on_packet)
            self._sniffer.start()
            self._running = True
            self._last_pkt_ts = time.time()
            self._err = ""
            return True, f"抓包已启动 ({iface})"
        except Exception as e:
            self._err = f"抓包启动失败: {e} (需要管理员权限 + Npcap)"
            return False, self._err

    def stop(self):
        self._user_stopped = True
        try:
            if self._sniffer:
                self._sniffer.stop()
        except Exception:
            pass
        self._sniffer = None
        self._running = False
        return True, "抓包已停止"

    def is_running(self):
        return self._running and self._sniffer is not None

    def force_revive(self, timeout=45):
        """热点重启前后主动重建抓包 (不等看门狗300秒空闲判定).

        关键: 必须抢在手机自动重连之前就绪 —— 重连只需2~4秒, 其间App的
        QUIC Initial 已发完. 快路径直接用 control_ref 已知 GUID 重试绑定
        (毫秒级, 网卡一出现立即就绪); find_ap_interface 含 PowerShell
        启动开销(0.5~2秒/次), 只作为 2秒一次的慢速校准兜底.
        阻塞等待, 供后台线程调用. 返回是否成功."""
        self._user_stopped = False
        self._restarting = True
        try:
            try:
                if self._sniffer:
                    self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
            self._running = False
            from . import hotspot
            deadline = time.time() + timeout
            ok, msg = False, "等待网卡超时"
            last_find = 0.0
            fails = 0
            while time.time() < deadline:
                # 快路径: 旧 GUID 直试 (Wi-Fi Direct 虚拟适配器 GUID 通常稳定)
                try:
                    ok, msg = self.start()
                except Exception as e:
                    ok, msg = False, str(e)
                if ok:
                    # 存活验证: 3秒内必须见到包 (热点开机后手机立即有
                    # ARP/DNS/TCP 流量). 网卡重置会令内核抓包线程静默死亡
                    # (_running=True 但零包), start"成功"不等于活着.
                    base = self._pkt_count
                    alive = False
                    for _ in range(6):
                        time.sleep(0.5)
                        if self._pkt_count > base:
                            alive = True
                            break
                    if alive:
                        break
                    ok, msg = False, "start后3秒零包(句柄静默死亡), 重试"
                    try:
                        if self._sniffer:
                            self._sniffer.stop()
                    except Exception:
                        pass
                    self._sniffer = None
                    self._running = False
                fails += 1
                if fails % 8 == 0:
                    # scapy conf.ifaces 是缓存枚举: 热点重启后新出现的
                    # 适配器需主动刷新才可见
                    try:
                        from scapy.all import conf
                        conf.ifaces.reload()
                    except Exception:
                        pass
                # 慢路径: 2秒一次 PS 校准 (防适配器重建后 GUID/IP 变化)
                if time.time() - last_find > 2.0:
                    last_find = time.time()
                    try:
                        ap = hotspot.find_ap_interface()
                        if ap and isinstance(self.control_ref, dict):
                            self.control_ref["ap_iface"] = ap
                    except Exception:
                        pass
                time.sleep(0.25)
            try:
                self.storage.log_event(
                    "system", "", "",
                    "热点重启后重建抓包: " + ("成功" if ok else f"失败({msg})"))
            except Exception:
                pass
            return ok
        finally:
            self._restarting = False

    def watchdog(self):
        """嗅探看门狗 (GUI 每30秒调用).

        网卡重置/热点开关会令 AsyncSniffer 内核抓包线程静默死亡 (仍 _running=True),
        表现为设备列表/流量永久冻结. 连续 120 秒零包即判定死亡并自动重建
        (热点开机后手机持续有流量, 120秒零包=必死; 原300秒太慢, 用户测试
        窗口内来不及自救); 热点未开启或用户手动停止时不接管."""
        if not self._running or self._user_stopped or self._restarting:
            return
        idle = time.time() - self._last_pkt_ts
        if idle < 120:
            return
        from . import hotspot
        if not hotspot.find_ap_interface():
            return                      # 热点未开启, 无包属正常
        try:
            self._restarting = True
            # force_revive 自带存活验证 (start成功但句柄静默死亡会重试)
            ok = self.force_revive(timeout=30)
            try:
                self.storage.log_event(
                    "system", "", "",
                    f"嗅探看门狗: 连续{int(idle)}秒零包, 自动重建抓包 "
                    + ("成功" if ok else "失败"))
            except Exception:
                pass
        finally:
            self._restarting = False

    def _resolve_iface(self):
        """按 GUID 把热点虚拟网卡映射到 Scapy 接口对象."""
        try:
            from scapy.all import conf
            guid = (self.control_ref.get("ap_iface") or {}).get("guid", "")
            if not guid:
                return None
            guid = "{" + guid.strip("{}") + "}"
            for obj in conf.ifaces.values():
                g = getattr(obj, "guid", "") or ""
                if g.strip("{}").lower() == guid.strip("{}").lower():
                    return obj
            return None
        except Exception:
            return None

    # ---------- 抓包回调 (Scapy 线程, 必须快) ----------
    def _on_packet(self, pkt):
        try:
            self._pkt_count += 1
            self._last_pkt_ts = time.time()
            d = self._diag
            d["pkt"] += 1
            if IP not in pkt:
                return
            ip = pkt[IP]
            tcp = pkt[TCP] if TCP in pkt else None
            udp = pkt[UDP] if UDP in pkt else None
            if tcp:
                proto, sport, dport, payload = 6, int(tcp.sport), int(tcp.dport), bytes(tcp.payload)
            elif udp:
                proto, sport, dport, payload = 17, int(udp.sport), int(udp.dport), bytes(udp.payload)
            else:
                proto, sport, dport, payload = int(ip.proto), 0, 0, b""
            eth = pkt[Ether] if Ether in pkt else None
            src_mac = (eth.src if eth is not None else "").lower()
            dst_mac = (eth.dst if eth is not None else "").lower()
            if proto == 17 and dport == 443:
                d["udp443"] += 1
                if len(payload) >= 1200 and (payload[0] & 0x80):
                    d["quic_long"] += 1
            ap_mac = str(self.control_ref.get("ap_mac") or "").replace("-", ":").lower()
            # 方向: 上行 = src 是客户端 (不是热点AP自己的MAC)
            if ap_mac and src_mac == ap_mac:
                client_mac = dst_mac
                direction = "down"
            else:
                client_mac = src_mac
                direction = "up"
            item = {
                "src_mac": src_mac, "dst_mac": dst_mac, "client_mac": client_mac,
                "direction": direction,
                "src": ip.src, "dst": ip.dst,
                "proto": proto, "sport": sport, "dport": dport,
                "payload": payload if (proto == 6 and (sport == 443 or dport == 443)
                                       and len(payload) > 6) else b"",
                "http": payload if (proto == 6 and (sport == 80 or dport == 80)
                                    and 0 < len(payload) <= 1600) else b"",
                "quic": payload if (proto == 17 and dport == 443
                                    and len(payload) >= 1200
                                    and (payload[0] & 0x80)) else b"",
                "tcp_seq": int(tcp.seq) if tcp else None,
                "tcp_ack": int(tcp.ack) if tcp else None,
                "dns": payload if (proto == 17 and (sport == 53 or dport == 53)) else b"",
                "dot": (proto == 6 and (sport == 853 or dport == 853)),
                "len": int(ip.len),
                "ip_bytes": bytes(ip),
                "ts": float(pkt.time),
            }
            with self._lock:
                self._queue.append(item)
                if len(self._queue) > 20000:
                    self._queue = self._queue[-15000:]
        except Exception:
            pass

    def _parse_loop(self):
        while True:
            time.sleep(0.4)
            with self._lock:
                batch, self._queue = self._queue, []
            if batch:
                for item in batch:
                    try:
                        self._process(item)
                    except Exception:
                        pass
                self._flush_flows()
            # 60秒打点: 嗅探层流量画像 (QUIC Initial 排查: udp443/quic_long)
            if time.time() - self._diag_ts > 60:
                self._diag_ts = time.time()
                d = self._diag
                if d["pkt"]:
                    try:
                        self.storage.log_event(
                            "system", "", "",
                            f"嗅探打点(60s): 包={d['pkt']} udp443={d['udp443']} "
                            f"quic长头部={d['quic_long']} 队列={len(self._queue)}")
                    except Exception:
                        pass
                    d["pkt"] = d["udp443"] = d["quic_long"] = 0

    # ---------- 解析与统计 ----------
    def _process(self, it):
        now = it["ts"]
        mac = it["client_mac"]
        if not mac or mac == "02:ff:ff:ff:ff:ff":
            return                      # ARP断流伪造MAC: 不是真实设备的流量
        tls = None
        # 1) 字节统计
        mb = self.mac_bytes.setdefault(mac, {"up": 0, "down": 0, "total": 0})
        if it["direction"] == "up":
            mb["up"] += it["len"]
            mb["total"] += it["len"]
            delta = (it["len"], 0)
        else:
            mb["down"] += it["len"]
            mb["total"] += it["len"]
            delta = (0, it["len"])
        win = self.mac_rate.setdefault(mac, deque(maxlen=64))
        win.append((now, delta[0], delta[1]))

        # 1.5) 实时活动上报 -> ClientMonitor.note_activity (上线更及时)
        if it["direction"] == "up" and it["src"]:
            if now - self._act_seen.get(mac, 0) > 2:
                self._act_seen[mac] = now
                cb = self.activity_cb
                if cb:
                    try:
                        cb(mac, it["src"])
                    except Exception:
                        pass

        # 2) 流表
        if it["direction"] == "up":
            key = (mac, it["src"], it["dst"], it["proto"], it["sport"], it["dport"])
            raddr = it["dst"]
        else:
            key = (mac, it["dst"], it["src"], it["proto"], it["dport"], it["sport"])
            raddr = it["src"]
        f = self.flows.get(key)
        if f is None:
            f = Flow(key, mac, it["src"] if it["direction"] == "up" else it["dst"],
                     raddr, it["proto"], key[4], key[5], now)
            self.flows[key] = f
        f.last_ts = now
        if it["direction"] == "up":
            f.bytes_up += it["len"]
        else:
            f.bytes_down += it["len"]

        # 3) DNS
        if it["dns"]:
            d = parse_dns(it["dns"])
            if d and not d["is_response"] and d["qname"]:
                dk = (mac, d["qname"])
                if time.time() - self.dns_seen.get(dk, 0) > 5:
                    self.dns_seen[dk] = time.time()
                    f.qname = d["qname"]
                    f.dnstype = d["qtype"]
                    f.category = f.category or "DNS"
                    self.storage.log_dns(mac, it["src"], d["qname"], d["qtype"],
                                         encrypted=False, ech_flag=d["https_rr"],
                                         answers=d["answers"])
                    # 域名黑名单由 control 在 GUI 线程外处理: 这里回调
                    if self.control_ref.get("on_dns_query"):
                        try:
                            self.control_ref["on_dns_query"](mac, it["src"], d)
                        except Exception:
                            pass
            elif d and d["is_response"] and d["answers"]:
                # DNS 应答: 查询包里没有IP, 真正能阻断的是应答里的 A/AAAA 记录
                cb = self.control_ref.get("on_dns_query")
                if cb:
                    try:
                        cb(mac, it["dst"], d)
                    except Exception:
                        pass
        if it.get("dot"):
            # DNS over TLS: 仅记录"使用了加密DNS"
            if time.time() - self.dns_seen.get((mac, "__DOT__"), 0) > 60:
                self.dns_seen[(mac, "__DOT__")] = time.time()
                self.storage.log_dns(mac, it["src"], "(DoT 加密DNS)", "853",
                                     encrypted=True, ech_flag=False, answers=[])

        # 4) TLS ClientHello
        if it["payload"] and (it["sport"] == 443 or it["dport"] == 443):
            tls = parse_tls_client_hello(it["payload"])
            if tls:
                f.sni = tls["sni"] or f.sni
                f.tls_version = tls["tls_version"]
                f.ja3 = f.ja3 or tls["ja3"]
                f.ech = f.ech or tls["ech"]
                f.esni = f.esni or tls["esni"]
                if tls["alpn"]:
                    f.alpn = ",".join(tls["alpn"])
                if tls["ech"] or tls["esni"]:
                    self.storage.log_dns(mac, it["src"], f.sni or "(ECH加密SNI)",
                                         "ECH", encrypted=True,
                                         ech_flag=True, answers=[])
                # 无明文DNS却出现SNI -> 标记加密DNS使用
                if f.sni and not any(k[0] == mac and k[1] == f.sni for k in self.dns_seen):
                    if f.sni not in self.dns_no_plaintext.setdefault(mac, set()):
                        self.dns_no_plaintext[mac].add(f.sni)
                        self.storage.log_dns(mac, it["src"], f.sni, "SNI(无明文DNS,疑似加密DNS)",
                                             encrypted=True, ech_flag=False, answers=[])
                if self.control_ref.get("on_tls_hello"):
                    try:
                        self.control_ref["on_tls_hello"](mac, it, tls)
                    except Exception:
                        pass

        # 5) 供 DPI (只保留前几个载荷)
        if len(f.payloads) < 8:
            f.payloads.append({
                "proto": it["proto"], "sport": it["sport"], "dport": it["dport"],
                "payload": it["payload"], "ip_bytes": it["ip_bytes"],
                "sni": f.sni or None,
            })

        # 6) 连接层阻断检查 (netkill: TLS SNI / HTTP Host / QUIC Initial
        #    + 断网设备任意TCP兜底RST)
        nk = self.control_ref.get("on_netkill")
        if nk and (tls or it.get("http") or it.get("quic")
                   or it.get("proto") == 6):
            try:
                nk(it, tls)
            except Exception:
                pass

    def _flush_flows(self):
        """分类未识别的流, 并把完成的流写入存储."""
        now = time.time()
        done_keys = []
        for key, f in self.flows.items():
            if f.category is None:
                try:
                    cat, detail = self.dpi.classify_flow(key, f.payloads)
                except Exception:
                    cat, detail = "Unknown", "dpi-error"
                f.category = cat
                f.detail = detail
                cb = self.control_ref.get("on_flow_classified")
                if cb and f.category not in ("Unknown", "DNS"):
                    try:
                        cb(f.mac, f.raddr, f.category)
                    except Exception:
                        pass
            idle = now - f.last_ts
            total = f.bytes_up + f.bytes_down
            if (idle > 10 and total > 0) or len(self.flows) > 3000:
                self.storage.log_flow(
                    mac=f.mac, ip=f.ip, proto=f.proto, sport=f.sport, dport=f.dport,
                    raddr=f.raddr, category=f.category or "Unknown",
                    detail=f.detail, bytes_up=f.bytes_up, bytes_down=f.bytes_down,
                    sni=f.sni, alpn=f.alpn, ja3=f.ja3,
                    ech=f.ech, esni=f.esni, tls_version=f.tls_version,
                    qname=f.qname, first_ts=f.first_ts, last_ts=f.last_ts)
                mc = self.mac_categories.setdefault(f.mac, {})
                mc[f.category or "Unknown"] = mc.get(f.category or "Unknown", 0) + total
                done_keys.append(key)
        for k in done_keys:
            self.flows.pop(k, None)

    # ---------- 查询 ----------
    def get_send_iface(self):
        """返回当前嗅探热点网卡的 Scapy 对象 (netkill L2 发送用)."""
        return self._iface_obj

    def get_rates(self):
        """mac -> {'down_bps','up_bps','total_bytes','up','down','categories'}"""
        now = time.time()
        out = {}
        for mac, win in self.mac_rate.items():
            up = down = 0
            span_up = span_down = 0
            for ts, du, dd in win:
                if now - ts <= 5:
                    up += du
                    down += dd
                    span_up += du
                    span_down += dd
            mb = self.mac_bytes.get(mac, {"up": 0, "down": 0, "total": 0})
            out[mac] = {
                "down_bps": span_down / 5.0,
                "up_bps": span_up / 5.0,
                "total_bytes": mb["total"],
                "up": mb["up"], "down": mb["down"],
                "categories": dict(self.mac_categories.get(mac, {})),
            }
        return out

    def get_active_flows(self, mac=None, limit=200):
        rows = []
        for key, f in sorted(self.flows.items(), key=lambda kv: -kv[1].last_ts):
            if mac and f.mac != mac:
                continue
            rows.append({
                "mac": f.mac, "ip": f.ip, "raddr": f.raddr, "proto": f.proto,
                "sport": f.sport, "dport": f.dport, "category": f.category or "识别中",
                "bytes_up": f.bytes_up, "bytes_down": f.bytes_down,
                "sni": f.sni, "alpn": f.alpn, "ja3": f.ja3,
                "ech": f.ech, "esni": f.esni, "tls_version": f.tls_version,
                "first_ts": f.first_ts, "last_ts": f.last_ts,
            })
            if len(rows) >= limit:
                break
        return rows

    def stats(self):
        now = time.time()
        if now - self._last_tick >= 1:
            self._pps = self._pkt_count / (now - self._last_tick)
            self._pkt_count = 0
            self._last_tick = now
        return {"running": self._running, "err": self._err, "pps": self._pps,
                "flows": len(self.flows), "iface": str(self._iface_obj)}

    def clear_device(self, mac):
        self.mac_bytes.pop(mac, None)
        self.mac_rate.pop(mac, None)
        self.mac_categories.pop(mac, None)
