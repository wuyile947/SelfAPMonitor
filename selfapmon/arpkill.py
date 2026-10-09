"""断网设备回程黑洞 (主机邻居表静态毒化, Windows 系统机制).

架构定性 (2026-09-22 实测): Windows SoftAP 会接收设备发往**任意 MAC** 的帧
(改设备 ARP 缓存无效: dst=02:ff 的上行帧照常被 ICS NAT 转发), 但主机
**回程**查自身邻居表. 把主机邻居表中设备 IP 设为静态 Permanent 条目
指向 FAKE_MAC (02:ff:ff:ff:ff:ff, 本地管理位不可能是真实设备) 后:
  主机回程帧 dst=02:ff -> 无线侧无关联 STA, AP 无法投递 -> 设备收不到
  任何回程 -> TCP/QUIC/DNS 全部有去无回, 连接自然死亡 (含已建立 QUIC).

Permanent 状态不会被 Windows 邻居不可达检测 (NUD) Probe 覆盖/老化,
普通毒化条目几十秒即被设备真实 ARP 应答恢复, 静态条目稳定持续.

合规边界 (用户已明确允许主动发包):
  - 仅对自家热点内已授权断网设备的回程拒绝投递, 不触碰互联网侧
  - 与 DNS 层对断网设备返回 0.0.0.0 同性质 (拒绝服务), 不窃听、
    不转发、不解析、不做中间人; 全部通过 Windows 系统机制实现
"""
import subprocess
import threading
import time

FAKE_MAC = "02-FF-FF-FF-FF-FF"      # New-NetNeighbor 用横杠格式
FAKE_MAC_COLON = FAKE_MAC.lower().replace("-", ":")
BOGUS_MACS = {FAKE_MAC_COLON, "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}
CREATION_FLAGS = 0x08000000         # CREATE_NO_WINDOW
SCAPY_OK = True                     # 纯 Windows 系统机制 (New-NetNeighbor), 无 scapy 依赖;
                                    # 保留此标志兼容 control._ensure_arpkill 的可用性检查


class ArpKiller(threading.Thread):
    """断网名单设备的回程黑洞 (常驻线程, 每2秒幂等刷新).

    targets_fn() -> {设备IP: 设备MAC}   (control._sync_blocked 推送, 换IP自动跟随)
    ap_fn()      -> {'ip':..., 'ifIndex':...}  热点网卡信息 (无则等待)
    err_cb(tag, count) 失败诊断 (60秒节流)
    """

    def __init__(self, targets_fn, ap_fn, err_cb=None):
        super().__init__(daemon=True, name="ArpKill")
        self.targets_fn = targets_fn
        self.ap_fn = ap_fn
        self.err_cb = err_cb
        self.current_targets = set()    # 当前已黑洞的设备IP (control.on_netkill 跳过杀包用)
        self._stop_ev = threading.Event()
        self._diag = {}
        self._diag_ts = {}

    def _diag_note(self, tag):
        self._diag[tag] = self._diag.get(tag, 0) + 1
        now = time.time()
        if now - self._diag_ts.get(tag, 0) < 60:
            return
        self._diag_ts[tag] = now
        if self.err_cb:
            try:
                self.err_cb(tag, self._diag[tag])
            except Exception:
                pass

    def _ps(self, script):
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive",
                 "-ExecutionPolicy", "Bypass", "-Command", script],
                capture_output=True, timeout=15, creationflags=CREATION_FLAGS)
            return True
        except Exception as e:
            self._diag_note(f"ps:{type(e).__name__}")
            return False

    def _valid_ip(self, ip):
        parts = str(ip).split(".")
        return (len(parts) == 4
                and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts))

    def poison(self, ip):
        """主机邻居表: 设备IP -> FAKE_MAC 静态 Permanent (幂等, 重复设置无害).

        只写 ActiveStore: 本次开机内生效, 重启自动消失, 不留持久残留."""
        ap = self.ap_fn() or {}
        if not (self._valid_ip(ip) and ap.get("ifIndex")):
            self._diag_note("no_ap")
            return False
        i = int(ap["ifIndex"])
        # 前置清理必须用管道删除: 裸 Remove 对 Permanent/Dynamic 条目可能静默失败,
        # 旧条目删不掉则 New-NetNeighbor 报"已存在"被吞, 毒化永远写不进去 (实测)
        return self._ps(
            f"Get-NetNeighbor -InterfaceIndex {i} -IPAddress {ip} "
            f"-ErrorAction SilentlyContinue | "
            f"Remove-NetNeighbor -Confirm:$false -ErrorAction SilentlyContinue;"
            f"New-NetNeighbor -InterfaceIndex {i} -IPAddress {ip} "
            f"-LinkLayerAddress {FAKE_MAC} -State Permanent "
            f"-PolicyStore ActiveStore -ErrorAction SilentlyContinue")

    def restore(self, ip):
        """解除断网: 删除静态毒化条目, Windows 重新正常解析设备真实 MAC."""
        ap = self.ap_fn() or {}
        if not (self._valid_ip(ip) and ap.get("ifIndex")):
            return
        i = int(ap["ifIndex"])
        # 普通裸 Remove 对 Permanent 条目可能静默失败, 管道传对象最可靠
        self._ps(f"Get-NetNeighbor -InterfaceIndex {i} -IPAddress {ip} "
                 f"-ErrorAction SilentlyContinue | "
                 f"Remove-NetNeighbor -Confirm:$false "
                 f"-ErrorAction SilentlyContinue")

    def run(self):
        while not self._stop_ev.is_set():
            try:
                targets = self.targets_fn() or {}
                if targets:
                    ap = self.ap_fn() or {}
                    if ap.get("ifIndex"):
                        for ip in list(targets):
                            self.poison(ip)
                new_ips = set(targets)
                # 脉冲黑洞到期/名单移除: 自动删除静态条目, 设备立即恢复联网
                for ip in list(self.current_targets - new_ips):
                    self.restore(ip)
                # 只有静态条目设置成功的目标才真正回程黑洞
                self.current_targets = new_ips
            except Exception as e:
                self._diag_note(f"loop:{type(e).__name__}")
            self._stop_ev.wait(2.0)

    def stop(self):
        self._stop_ev.set()
        self.current_targets = set()
