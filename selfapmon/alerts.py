"""告警: 陌生设备 / 流量突增 / 配额超限 (带冷却去重)."""

import time


class AlertManager:
    def __init__(self, config, on_alert, storage):
        """
        on_alert: fn(kind, mac, msg)  -> GUI 队列 (UI线程弹窗/显示)
        storage:  Storage (事件入库)
        """
        self.config = config
        self.on_alert = on_alert
        self.storage = storage
        self._cooldown = {}      # (kind, mac) -> last_ts
        self._spike_streak = {}  # mac -> 连续超阈值计数

    def _fire(self, kind, mac, msg, popup=True):
        now = time.time()
        cd = float(self.config.get("alert_cooldown_sec"))
        key = (kind, mac)
        if now - self._cooldown.get(key, 0) < cd:
            return
        self._cooldown[key] = now
        self.storage.log_event("alert", mac, "", f"[{kind}] {msg}")
        self.on_alert(kind, mac, msg, popup)

    # ---- 陌生设备 ----
    def client_up(self, mac, ip):
        if self.config.is_blacklisted(mac):
            self._fire("黑名单设备", mac, f"黑名单设备接入! MAC={mac} IP={ip}")
            return "blacklist"
        if not self.config.is_whitelisted(mac):
            self._fire("陌生设备", mac, f"发现陌生设备接入热点: MAC={mac} IP={ip}", popup=True)
            return "unknown"
        return "known"

    # ---- 流量突增 ----
    def rate_sample(self, mac, down_bps):
        threshold = float(self.config.get("rate_spike_bps"))
        need = int(self.config.get("spike_windows"))
        if down_bps > threshold:
            n = self._spike_streak.get(mac, 0) + 1
            self._spike_streak[mac] = n
            if n == need:
                mbps = down_bps / 1048576
                self._fire("流量突增", mac,
                           f"设备 {mac} 下行速率持续超过 {threshold/1048576:.1f} MB/s "
                           f"(当前 {mbps:.1f} MB/s)")
        else:
            self._spike_streak[mac] = 0

    # ---- 配额 ----
    def quota_check(self, mac, total_bytes):
        quota_mb = self.config.get_quota_mb(mac)
        if not quota_mb:
            return None
        used_mb = total_bytes / 1048576
        if used_mb >= quota_mb:
            self._fire("配额超限", mac,
                       f"设备 {mac} 已用流量 {used_mb:.1f}MB 超过配额 {quota_mb:.0f}MB")
            return "exceeded"
        if used_mb >= quota_mb * 0.9:
            self._fire("配额预警", mac,
                       f"设备 {mac} 已用流量 {used_mb:.1f}MB 达到配额 {quota_mb:.0f}MB 的 90%")
            return "warn"
        return None
