"""接入设备发现与在线监控.

Windows 移动热点没有公开"客户端列表"API, 采用实践方案:
  1. Get-NetNeighbor 读取热点虚拟网卡上的 ARP 邻居表 (结构化 JSON, 不受系统语言影响)
  2. 对可达状态的邻居并发 ping (绑定热点网卡源IP) 确认在线
  3. MonitorThread 周期刷新, 产生 上线/下线 事件
"""
import json
import subprocess
import threading
import time
from datetime import datetime

from . import hotspot
from .arpkill import BOGUS_MACS


def _run_ps(script, timeout=30):
    cmd = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
           "-EncodedCommand", script]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        out = p.stdout.decode("utf-8", errors="replace").strip()
        if out.startswith("\ufeff"):
            out = out[1:]
        return out
    except Exception:
        return ""


def _b64(ps: str) -> str:
    import base64
    return base64.b64encode(ps.encode("utf-16-le")).decode("ascii")


PS_NEIGHBORS = """
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$target = @()
if ('{AP_ALIAS}' -ne '') { $target = Get-NetNeighbor -InterfaceAlias '{AP_ALIAS}' -AddressFamily IPv4 }
else {
  $ifs = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*Microsoft Wi-Fi Direct Virtual*' }
  foreach ($i in $ifs) { $target += Get-NetNeighbor -InterfaceIndex $i.ifIndex -AddressFamily IPv4 }
}
@($target | Where-Object { $_.IPAddress -notmatch '^(169\\.254|224\\.|239\\.|255\\.)' -and $_.IPAddress -ne '' } |
  Select-Object IPAddress, LinkLayerAddress, State) | ConvertTo-Json -Compress
"""

ONLINE_STATES = {"Reachable", "Stale", "Probe", "Delay", "Permanent"}


class Client:
    """单个接入设备."""
    __slots__ = ("mac", "ip", "first_seen", "last_seen", "online", "note")

    def __init__(self, mac, ip):
        self.mac = mac.lower()
        self.ip = ip
        self.first_seen = time.time()
        self.last_seen = self.first_seen
        self.online = True
        self.note = ""  # 白名单/黑名单/陌生/配额超限 等标记

    def as_dict(self):
        return {
            "mac": self.mac, "ip": self.ip,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "online": self.online, "note": self.note,
        }


class ClientMonitor(threading.Thread):
    """周期性扫描热点客户端, 通过回调上报事件 (线程安全)."""

    def __init__(self, config, on_event, interval=5.0):
        super().__init__(daemon=True, name="ClientMonitor")
        self.config = config
        self.on_event = on_event            # fn(event_type:str, client:Client)
        self.interval = interval
        self.clients = {}                   # mac -> Client
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.hotspot_status = {}            # 最近一次热点状态
        self.ap_iface = None                # 最近一次热点网卡信息
        self._snapshot_hook = None          # 注入流量统计 (由 sniffer 提供)

    def stop(self):
        self._stop.set()

    def set_rate_hook(self, fn):
        """fn(mac) -> (down_bps, up_bps, total_bytes, category_stats)"""
        self._snapshot_hook = fn

    # ---- 扫描 ----
    def _scan_neighbors(self):
        alias = ""
        if self.config.get("ap_interface_alias"):
            alias = self.config.get("ap_interface_alias")
        script = PS_NEIGHBORS.replace("{AP_ALIAS}", alias)
        out = _run_ps(_b64(script))
        if not out:
            return []
        try:
            data = json.loads(out)
            rows = data if isinstance(data, list) else ([data] if isinstance(data, dict) else [])
        except Exception:
            return []
        result = []
        for r in rows:
            ip = str(r.get("IPAddress", "")).strip()
            mac = str(r.get("LinkLayerAddress", "")).strip().lower().replace("-", ":")
            state = str(r.get("State", "")).strip()
            if not ip or not mac or mac in BOGUS_MACS:
                continue
            if state and state not in ONLINE_STATES:
                # Incomplete/Unreachable 不算在线, 但仍返回用于交叉判断
                result.append((mac, ip, False))
            else:
                result.append((mac, ip, True))
        return result

    def _ping_one(self, ip):
        """单设备 ping 探测 (绑定热点源IP), 设备数通常 <= 10, 串行足够."""
        src_ip = (self.ap_iface or {}).get("ip", "")
        cmd = ["ping", "-n", "1", "-w", "400"]
        if src_ip:
            cmd += ["-S", src_ip]
        cmd.append(ip)
        try:
            p = subprocess.run(cmd, capture_output=True, timeout=3,
                               creationflags=subprocess.CREATE_NO_WINDOW)
            return (p.returncode == 0) and (b"TTL=" in p.stdout or b"ttl=" in p.stdout)
        except Exception:
            return False

    def scan_once(self):
        """扫描一次, 返回本轮发现的 (mac, ip) 列表; 产生上下线事件."""
        self.ap_iface = hotspot.find_ap_interface()
        neighbors = self._scan_neighbors()
        seen = {}
        for mac, ip, state_ok in neighbors:
            seen.setdefault(mac, ip)
        # ping 验证 (邻居表里的 Stale 可能已离开)
        confirmed = {}
        for mac, ip in seen.items():
            if self._ping_one(ip):
                confirmed[mac] = ip
        if not confirmed:
            # 邻居表状态为 Reachable 的仍然保留 (ping 可能被客户端防火墙拦)
            for mac, ip, state_ok in neighbors:
                if state_ok and mac not in confirmed:
                    confirmed[mac] = ip

        events = []
        now = time.time()
        with self._lock:
            # 新上线
            for mac, ip in confirmed.items():
                if mac not in self.clients:
                    c = Client(mac, ip)
                    self.clients[mac] = c
                    events.append(("client_up", c))
                else:
                    c = self.clients[mac]
                    if not c.online:
                        c.online = True
                        events.append(("client_up", c))
                    c.ip = ip
                    c.last_seen = now
            # 下线
            for mac, c in list(self.clients.items()):
                if mac not in confirmed and c.online:
                    c.online = False
                    c.last_seen = now
                    events.append(("client_down", c))
        return confirmed, events

    def refresh_hotspot_status(self):
        r = hotspot.get_status()
        if r.ok:
            self.hotspot_status = r.data
        return self.hotspot_status

    def note_activity(self, mac, ip):
        """嗅探到设备实时流量 -> 立即标记/添加在线 (比轮询及时, 供解析线程调用)."""
        mac = str(mac).lower()
        if mac in BOGUS_MACS:
            return                      # ARP断流的伪造MAC不是真实设备
        now = time.time()
        with self._lock:
            c = self.clients.get(mac)
            if c is None:
                c = Client(mac, ip)
                self.clients[mac] = c
                etype = "client_up"
            elif not c.online:
                c.online = True
                c.last_seen = now
                etype = "client_up"
            else:
                if ip:
                    c.ip = ip
                c.last_seen = now
                return
        try:
            self.on_event(etype, c)
        except Exception:
            pass

    def run(self):
        while not self._stop.is_set():
            try:
                _, events = self.scan_once()
                for etype, client in events:
                    try:
                        self.on_event(etype, client)
                    except Exception:
                        pass
                self.refresh_hotspot_status()
            except Exception:
                pass
            self._stop.wait(self.interval)

    # ---- 查询 ----
    def get_clients(self):
        with self._lock:
            return {m: c.as_dict() for m, c in self.clients.items()}

    def get_client(self, mac):
        with self._lock:
            return self.clients.get(str(mac).lower())
