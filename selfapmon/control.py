"""管控动作编排: 断网/恢复/踢除/限速/配额/域名黑名单/类型阻断.

设计原则:
  - 通过 Windows 系统机制 (DNS解析层/QoS/热点开关) + 协议内连接终止
    报文 (netkill: TCP RST / QUIC VN, 用户明确允许主动发包) 实现
  - 不伪造业务数据, 不解密内容, 不做中间人
  - 设备断网/踢除: DNS级 + 连接层全杀 (实测防火墙/QoS/ipsec对热点NAT
    转发流量均无效; QUIC已建立连接需重启热点彻底断开, 见 hard_kill)
  - 域名黑名单/广告净化: DNS过滤层 解析即拦截 (返回0.0.0.0)
"""
import threading
import time

from . import firewall


class ControlCenter:
    def __init__(self, config, storage, alerts, sniffer, client_monitor, ui_queue):
        self.config = config
        self.storage = storage
        self.alerts = alerts
        self.sniffer = sniffer
        self.monitor = client_monitor
        self.ui_queue = ui_queue          # UI 线程消费: dict(type='toast'|...)
        self.blocked_macs = set()          # 已断网设备 (DNS级)
        self.portal_macs = {}              # 弹出指定页面: {mac: redirect_url}
        self.quota_exceeded = set()
        self.category_blocks = {}          # (mac, raddr) -> ts  识别去重
        self._pulse_ips = {}               # ip -> expire_ts  脉冲黑洞 (存量连接清理)
        self._pulse_seen = {}              # ip -> ts  脉冲触发节流
        self._ad_suspect = {}              # (mac, raddr) -> {sni, ts, state}  广告嫌疑(共用域名)
        self._blk_seen = {}                # (mac, 规则) -> [last_ts, 抑制次数]  阻断日志聚合
        self._lock = threading.Lock()

        # 供 sniffer 回调
        self._sniff_cb = {
            "on_dns_query": self.on_dns_query,
            "on_tls_hello": self.on_tls_hello,
        }
        self.dnsfilter = None               # DNSFilter 实例 (DNS过滤开关)
        self.netkill = None                 # NetKiller 实例 (连接层RST/VN注入)
        self.arpkill = None                 # ArpKiller 实例 (断网设备ARP断流)
        self.warnpage = None                # WarnPageServer 实例 (断网警告页)

    # ============ 设备级断网 (DNS级, 唯一对转发流量有效的机制) ============

    def _ensure_dnsfilter(self):
        """确保过滤DNS线程在运行 (断网/域名拦截的执行层). 返回是否可用."""
        if self.dnsfilter and self.dnsfilter.is_alive():
            return True
        self.set_dns_filter(True)
        return bool(self.dnsfilter and self.dnsfilter.is_alive())

    def _sync_blocked_ips(self):
        """blocked_macs -> 当前IP集合: DNS层推IP名单, 连接层推IP+MAC
        (MAC 由嗅探包自带, 设备重连换IP的窗口期也能立即杀)."""
        with self._lock:
            macs = list(self.blocked_macs)
        ips = set()
        for m in macs:
            c = self.monitor.get_client(m)
            if c and c.ip:
                ips.add(c.ip)
        portal_ips = set()
        for m in self.portal_macs:
            c = self.monitor.get_client(m)
            if c and c.ip:
                portal_ips.add(c.ip)
        if self.dnsfilter and self.dnsfilter.is_alive():
            try:
                self.dnsfilter.set_blocked_ips(ips)
                self.dnsfilter.set_portal_ips(portal_ips)
            except Exception:
                pass
        if self.netkill and self.netkill.is_alive():
            try:
                self.netkill.set_blocked_ips(ips)
                self.netkill.set_blocked_macs(macs)
            except Exception:
                pass
        if macs:
            try:
                self._ensure_arpkill()      # 断网设备上行断流 (杀已建立QUIC连接)
            except Exception:
                pass                        # 断网链路不能因单层失败而中断

    def _ensure_arpkill(self):
        """确保 ARP 毒化器在运行 (断网名单执行层, 常驻但无目标时不发包).

        原理: 对断网设备单播伪造 ARP 应答 (网关IP->无效MAC), 其上行
        (含 QUIC 1-RTT 心跳) 全部发不出 -> 服务端 keep-alive 断供,
        按 idle timeout 丢弃连接 -> App 重连握手撞上 netkill 火力."""
        if not self.config.get("arp_kill_enabled"):
            return False
        if self.arpkill and self.arpkill.is_alive():
            return True
        try:
            from . import arpkill as _ak
            if not _ak.SCAPY_OK:
                return False
        except Exception:
            return False

        def _targets():
            out = {}
            with self._lock:
                macs = list(self.blocked_macs)
                now = time.time()
                pulse = {ip for ip, exp in self._pulse_ips.items() if exp > now}
            portal_macs = set(self.portal_macs)     # 弹页设备豁免: 301响应需回程送达
            for m in macs:
                if m in portal_macs:
                    continue
                c = self.monitor.get_client(m)
                if c and getattr(c, "ip", ""):
                    out[c.ip] = m
            for ip in pulse:
                out.setdefault(ip, "")      # 脉冲黑洞设备 (可能无MAC对应)
            return out

        ak = _ak.ArpKiller(
            targets_fn=_targets,
            ap_fn=lambda: self.monitor.ap_iface or {},
            err_cb=self._arpkill_err)
        ak.start()
        self.arpkill = ak
        self.storage.log_event("control", "", "",
                               "ARP断流已就绪: 断网设备回程将被黑洞 "
                               "(主机静态邻居表, 杀已建立QUIC连接)")

    def _arpkill_err(self, tag, count):
        self.storage.log_event("control", "", "",
                               f"ARP断流诊断: {tag} (累计{count}次)")

    def set_arp_kill(self, enabled):
        """开关 ARP 断流层: 关闭时立即恢复所有在毒化设备的真实网关 MAC."""
        if enabled:
            self.config.set("arp_kill_enabled", True)
            if self.blocked_macs:
                self._ensure_arpkill()
                self.storage.log_event("control", "", "",
                                       "ARP断流开启: 断网设备上行将被切断")
            else:
                self.storage.log_event("control", "", "", "ARP断流开启 (待命)")
            self._toast("ARP断流", "已开启: 断网设备上行(含QUIC心跳)将被切断")
        else:
            self.config.set("arp_kill_enabled", False)
            ak = self.arpkill
            if ak:
                for ip in list((ak.targets_fn() or {})):
                    try:
                        ak.restore(ip)          # 删静态毒化条目
                    except Exception:
                        pass
                ak.stop()
                self.arpkill = None
            self.storage.log_event("control", "", "", "ARP断流关闭, 已恢复设备ARP")
            self._toast("ARP断流", "已关闭并恢复设备ARP")

    def _maybe_pulse_blackhole(self, ip, mac=""):
        """脉冲黑洞: 短时黑洞命中黑名单设备的存量连接池, 到期自动撤销.

        场景: 抖音/微信类 App 已建立的 QUIC 连接池 (1-RTT) 三层锁抓不住,
        命中黑名单规则时对该设备开 blackhole_pulse_sec 秒黑洞, 存量连接
        因收不到回程超时死亡; 撤销后设备恢复上网, 其后任何访问黑名单资源
        的新连接重新走 DNS/握手, 撞进 DNS+VN+RST 三层锁."""
        if not ip or not self.config.get("arp_kill_enabled"):
            return
        if mac and mac in self.portal_macs:
            return                  # 弹页设备豁免: 黑洞会吃掉301响应, 弹页出不来
        if mac and mac in self.blocked_macs:
            return                  # 已长期断网(持续黑洞), 无需脉冲
        sec = int(self.config.get("blackhole_pulse_sec") or 0)
        if sec <= 0:
            return
        now = time.time()
        with self._lock:
            if self._pulse_seen.get(ip, 0) > now - 120:
                return                      # 同设备 120 秒内只脉冲一次
            self._pulse_seen[ip] = now
            self._pulse_ips[ip] = now + sec
            for k in [k for k, t in self._pulse_seen.items()
                      if t < now - 600]:
                self._pulse_seen.pop(k, None)
        self._ensure_arpkill()
        self.storage.log_event("control", mac, ip,
                               f"脉冲黑洞 {sec}秒: 清理存量连接池 "
                               "(到期自动撤销, 设备恢复上网)")

    def _mac_by_ip(self, ip):
        for m, c in self.monitor.get_clients().items():
            if c.get("ip") == ip:
                return m
        return ""

    def block_internet(self, mac):
        """断网: DNS级(解析返回0.0.0.0) + 连接层全杀(RST/VN, 补HTTPDNS绕过).

        彻底断开请重启热点或修改热点密码."""
        c = self.monitor.get_client(mac)
        ip = c.ip if c else ""
        with self._lock:
            self.blocked_macs.add(mac)
        started = self._ensure_dnsfilter()
        if self.config.get("conn_kill_enabled"):
            self._ensure_netkill()          # 连接层全杀补HTTPDNS绕过
        if self.config.get("warn_page_enabled"):
            if self.dnsfilter and self.dnsfilter.is_alive():
                self.dnsfilter.warn_ip_fn = lambda: (
                    self.monitor.ap_iface or {}).get("ip", "")
        self._sync_blocked_ips()
        msg = ("DNS级断网+连接层全杀已生效" if started
               else "已加入断网名单, 但DNS过滤未运行, 请开启DNS过滤")
        if self.config.get("warn_page_enabled"):
            msg += " (警告页已开启: 设备访问网页将显示提示页)"
        self.storage.log_event("control", mac, ip,
                               f"断网: {msg} (解析拦截+TCP RST/QUIC VN)")
        self._toast("断网", f"{mac}: {msg}; 彻底断开请重启热点")
        return msg

    def unblock_internet(self, mac):
        with self._lock:
            self.blocked_macs.discard(mac)
            self.quota_exceeded.discard(mac)
        if self.arpkill:
            c = self.monitor.get_client(mac)
            if c and c.ip:
                try:
                    self.arpkill.restore(c.ip)    # 删静态毒化条目
                except Exception:
                    pass
        self._sync_blocked_ips()
        self.storage.log_event("control", mac, "", "恢复外网(DNS)")
        self._toast("恢复", f"{mac}: 已恢复域名解析")
        return "已恢复"

    def kick(self, mac):
        """踢除 = DNS级断网 + 连接层全杀 (Windows 无断开热点客户端的公开API)."""
        msg = self.block_internet(mac)
        self.storage.log_event("control", mac, "",
                               "踢除: 解析拦截+连接层RST/VN全杀; 已建立的QUIC连接"
                               "无法协议内终止, 彻底断开请用\"彻底断网(重启热点)\"")
        return msg

    def hard_kill(self, mac):
        """彻底断网 = 先加入断网名单, 再重启热点杀死全部既有连接.

        原理: QUIC 已建立连接(1-RTT)无合法协议内终止手段(VN 需 version 字段,
        stateless reset 需服务端密钥); 重启热点使全部既有连接死亡, 设备重连后
        ARP断流立即毒化其上行 (不依赖嗅探就绪窗口), 新 Initial/TCP/DNS 同时
        被 ARP/RST/VN/DNS 四层火力封杀, App 立即死透."""
        if mac in self.portal_macs:
            # 弹页与黑洞互斥: 黑洞吃掉全部回程, 301/页面永远送不到设备
            self.portal_macs.pop(mac, None)
            self.config.set("portal_redirects", dict(self.portal_macs))
            self._sync_portal_url()
            self.storage.log_event("control", mac, "",
                                   "彻底断网: 已自动清除该设备的弹出页面 "
                                   "(黑洞断流与弹页互斥)")
            self._toast("弹出页面", "该设备弹页已取消 (与彻底断网互斥)")
        self.block_internet(mac)
        stop_sec = max(3, int(self.config.get("hard_kill_stop_sec") or 5))
        self.storage.log_event("control", mac, "",
                               f"彻底断网: 重启热点中 (停机{stop_sec}秒)...")
        self._toast("彻底断网", f"热点重启中(约{stop_sec + 10}秒), 全部设备短暂掉线...")
        try:
            from . import hotspot
            hotspot.stop()
            # 短试一次 (万一网卡随热点关闭仍存在则提前就绪; 实测通常消失)
            try:
                self.sniffer.force_revive(timeout=3)
            except Exception:
                pass
            time.sleep(stop_sec)
            hotspot.start()
            # 阻塞等网卡出现并绑定: 快路径毫秒级重试 (无PS开销), 网卡出现后
            # ~0.3秒就绪, 抢在手机重连发Initial (AP广播后3~5秒) 之前
            try:
                self.sniffer.force_revive(timeout=45)
                self._sync_blocked_ips()
            except Exception:
                pass
            self.storage.log_event("control", mac, "",
                                   "彻底断网: 热点已重启, 断网名单继续生效")
            self._toast("彻底断网", "热点已重启; 目标设备重连后立即被全杀")
        except Exception as e:
            self.storage.log_event("control", mac, "", f"热点重启失败: {e}")
            self._toast("彻底断网", f"热点重启失败: {e}; 请手动开关热点")

    def limit_rate(self, mac, mbps):
        c = self.monitor.get_client(mac)
        ip = c.ip if c else ""
        msg = firewall.apply_rate_limit(mac, ip, mbps)
        self.storage.log_event("control", mac, ip, f"QoS限速 {mbps}MBps: {msg}")
        self._toast("限速", f"{mac}: {msg}")
        return msg

    def remove_rate_limit(self, mac):
        msg = firewall.remove_rate_limit(mac)
        self.storage.log_event("control", mac, "", f"取消限速: {msg}")
        self._toast("限速", f"{mac}: {msg}")
        return msg

    def set_quota(self, mac, mb):
        self.config.set_quota(mac, mb)
        self.storage.log_event("control", mac, "", f"设置流量配额 {mb}MB")
        self._toast("配额", f"{mac}: 配额 {mb}MB")
        return f"配额已设置: {mb}MB"

    def clear_quota(self, mac):
        self.config.clear_quota(mac)
        with self._lock:
            self.quota_exceeded.discard(mac)
        return "配额已清除"

    def is_blocked(self, mac):
        return mac in self.blocked_macs

    def set_force_plain_dns(self, enabled):
        """强制降级开关: 阻断853出站 + DoH服务商SNI阻断 (DoH靠 on_tls_hello)."""
        ap = self.config.get("ap_interface_alias") or firewall.get_ap_alias()
        msg = firewall.set_force_plain_dns(bool(enabled), ap)
        self.storage.log_event("control", "", "",
                               f"加密DNS强制降级 {'开启' if enabled else '关闭'}: {msg}")
        self._toast("强制降级", msg)
        return msg

    def unblock_all(self):
        """一键恢复: 解除全部断网/踢除, 清空域名/类型识别状态, 清理遗留防火墙规则."""
        with self._lock:
            macs = list(self.blocked_macs)
            self.blocked_macs.clear()
            self.quota_exceeded.clear()
            self._ad_suspect.clear()
            self._blk_seen.clear()
            self.category_blocks.clear()
            self.portal_macs.clear()        # 一键恢复: 解除全部弹出页面
        if self.portal_macs or True:
            self.config.set("portal_redirects", {})
            self._sync_portal_url()
        self._sync_blocked_ips()
        if self.arpkill:
            for mac in macs:
                c = self.monitor.get_client(mac)
                if c and c.ip:
                    try:
                        self.arpkill.restore(c.ip)
                    except Exception:
                        pass
        msg = firewall.unblock_all()      # 仅清理历史版本遗留的阻断规则 (保留FPD)
        for mac in macs:
            self.storage.log_event("control", mac, "", "一键恢复(批量解除阻断)")
        self._toast("恢复", f"已解除 {len(macs)} 台设备的断网" if macs else msg)
        return msg

    # ============ DNS过滤 (热点侧解析拦截, 不修改主机DNS) ============

    def set_dns_filter(self, enabled):
        """开关热点侧过滤DNS: 绑定AP网关IP:53 (与ICS共存, 优先接收客户端查询).

        开启时顺带自愈: 主机适配器若残留指向127.0.0.1的DNS (旧版本遗留), 复位."""
        from . import dnsfilter
        if enabled:
            if self.dnsfilter and self.dnsfilter.is_alive():
                return
            if dnsfilter.host_dns_stuck():          # 旧版本残留自愈
                dnsfilter.restore_host_dns({})
                self.storage.log_event("control", "", "",
                                       "自愈: 主机适配器残留127.0.0.1 DNS已复位")
            dfs = dnsfilter.DNSFilter(self.config, blocked_cb=self._dnsf_blocked)
            dfs.ap_ip_fn = lambda: (self.monitor.ap_iface or {}).get("ip", "")
            try:
                ups = sorted({s for v in dnsfilter.get_upstreams().values()
                              for s in v if s and s != "127.0.0.1"})
            except Exception:
                ups = []
            dfs.upstreams = ups
            dfs.start()
            time.sleep(0.3)
            if not dfs.is_alive():
                self._toast("DNS过滤", "启动失败: 热点网关53端口绑定失败 (请确认热点已开启)")
                return
            self.dnsfilter = dfs
            if self.config.get("warn_page_enabled"):
                dfs.warn_ip_fn = lambda: (self.monitor.ap_iface or {}).get("ip", "")
            self._sync_blocked_ips()
            self.storage.log_event("control", "", "",
                                   f"DNS过滤开启 (绑定{dfs.bound_ip or 'AP_IP'}:53, "
                                   f"上游: {','.join(dfs.upstreams[:2]) or '默认'})")
            self._toast("DNS过滤",
                        "已开启: 命中黑名单/短视频/广告SDK或已断网设备的域名, "
                        "解析时直接返回0.0.0.0")
        else:
            if self.dnsfilter:
                self.dnsfilter.stop()
                self.dnsfilter = None
            self.storage.log_event("control", "", "", "DNS过滤关闭")
            self._toast("DNS过滤", "已关闭")

    def _dnsf_blocked(self, qname, rule, src_ip=""):
        """DNSFilter 拦截回调 (聚合同规则日志)."""
        if rule == "弹页劫持":
            return                          # 弹出指定页面设备: 不触发脉冲/黑名单逻辑
        mac = self._mac_by_ip(src_ip) if src_ip else ""
        self._maybe_pulse_blackhole(src_ip, mac)   # 黑名单命中: 清理存量连接池
        log_now, prev = self._hit_once(mac or src_ip or "?", f"DNSF:{rule}")
        if log_now:
            extra = f"; 60秒内另有 {prev} 次同类命中" if prev else ""
            self.storage.log_event("block", mac, src_ip or "",
                                   f"DNS过滤拦截: {qname} (规则:{rule}) "
                                   f"-> 返回0.0.0.0{extra}")

    # ============ 连接层阻断 (RST/VN注入, 补HTTPDNS绕过) ============

    def _ensure_netkill(self):
        """确保连接阻断器在运行. 返回是否可用."""
        if self.netkill and self.netkill.is_alive():
            return True
        self.set_conn_kill(True)
        return bool(self.netkill and self.netkill.is_alive())

    def set_conn_kill(self, enabled):
        """开关连接层阻断: 命中规则的连接注入 RST/VN; 断网/踢除设备全杀.

        HTTPDNS 可绕过 DNS 过滤层, 但业务连接仍暴露 SNI/Host/QUIC SNI,
        连接建立即被主动终止, 业务持续失败 (用户已明确允许主动发包)."""
        if enabled:
            if self.netkill and self.netkill.is_alive():
                return
            from . import netkill
            if not netkill.SCAPY_OK:
                self.storage.log_event("control", "", "", "连接阻断启动失败: Scapy不可用")
                return
            nk = netkill.NetKiller(self.config,
                                   iface_fn=self.sniffer.get_send_iface,
                                   kill_cb=self._netkill_log,
                                   err_cb=self._netkill_err)
            nk.start()
            self.netkill = nk
            self._sync_blocked_ips()        # 已断网设备 -> 连接层全杀名单
            self.storage.log_event("control", "", "",
                                   "连接阻断开启: 命中域名黑名单/短视频规则的连接 "
                                   "将注入TCP RST/QUIC VN终止; 断网/踢除设备全杀 "
                                   "(补HTTPDNS绕过)")
            self._toast("连接阻断",
                        "已开启: 对命中黑名单/短视频域名的连接主动发RST/VN终止; "
                        "仅作用于自家热点客户端, 不解密内容")
        else:
            if self.netkill:
                self.netkill.stop()
                self.netkill = None
            self.storage.log_event("control", "", "", "连接阻断关闭")
            self._toast("连接阻断", "已关闭")

    def _netkill_err(self, tag, count, it):
        """NetKiller 失败诊断 (60秒每tag一条)."""
        self.storage.log_event("control", it.get("client_mac", "") if it else "",
                               it.get("src", "") if it else "",
                               f"连接阻断诊断: {tag} (累计{count}次)")

    def _netkill_log(self, kind, domain, rule, it):
        """NetKiller 击杀回调 (聚合同规则日志)."""
        mac = it.get("client_mac", "")
        ip = it.get("src", "")
        self._maybe_pulse_blackhole(ip, mac)       # 黑名单命中: 清理存量连接池
        log_now, prev = self._hit_once(mac or ip or "?",
                                       f"连接:{kind}:{domain}")
        if log_now:
            extra = f"; 60秒内另有 {prev} 次同类命中" if prev else ""
            way = ("TCP RST" if kind == "rst" else "QUIC VN")
            self.storage.log_event("block", mac, ip,
                                   f"连接阻断({way}): {domain} (规则:{rule}) "
                                   f"-> 连接已终止{extra}")

    def on_netkill(self, it, tls):
        """嗅探解析线程回调: 路由到 NetKiller 检查 (必须快, 不做阻塞操作)."""
        ak = self.arpkill
        if ak and ak.is_alive() and it.get("src") in ak.current_targets:
            return          # 回程黑洞生效中: RST/VN 发了也到不了设备, 跳过省资源
        nk = self.netkill
        if not (nk and nk.is_alive()):
            return
        if tls and tls.get("sni"):
            nk.on_tls(it, tls["sni"])
        elif it.get("http"):
            nk.on_http(it)
        elif it.get("quic"):
            nk.on_quic(it)
        elif (nk.has_blocked() and it.get("proto") == 6
              and it.get("direction") == "up"):
            nk.on_tcp_any(it)               # 断网设备: 任意TCP兜底RST

    # ============ 嗅探回调 (解析线程调用) ============

    def on_dns_query(self, mac, ip, dns_info):
        """明文 DNS 查询 -> 域名黑名单/广告SDK 检查 + (应答)IP 阻断."""
        if not (self.config.get("domain_block_enabled")
                or self.config.get("block_short_video")
                or self.config.get("ad_purify_enabled")):
            return
        qname = dns_info.get("qname", "")
        hit = self.config.match_domain_blacklist(qname)
        if hit:
            # 同设备同规则 60 秒内只记一条, 其余累计 (防止App换子域名重试刷屏)
            log_now, prev = self._hit_once(mac, f"域名:{hit}")
            if log_now:
                extra = f"; 60秒内另有 {prev} 次同类命中" if prev else ""
                self.storage.log_event("block", mac, ip,
                                       f"DNS黑名单命中: {qname} (规则:{hit}){extra}")
                self._toast("域名阻断", f"{mac} 查询了黑名单域名 {qname}{extra}, 已准备阻断其连接")
            # 该查询的应答 A 记录立即阻断 (无应答时靠 TLS SNI 兜底)
            for raddr in dns_info.get("answers", []):
                self._block_pair(mac, raddr, reason=f"domain:{qname}")
            return
        # 网络净化: 广告SDK域名 (确定性直接拦; 共用域名登记待流量推断)
        if self.config.get("ad_purify_enabled"):
            ad = self.config.match_ad_sdk(qname)
            if ad:
                kind, rule = ad
                if kind == "definite":
                    log_now, _ = self._hit_once(mac, f"广告:{rule}")
                    if log_now:
                        self.storage.log_event("block", mac, ip,
                                               f"广告SDK命中: {qname} (规则:{rule})")
                    for raddr in dns_info.get("answers", []):
                        self._block_pair(mac, raddr, reason=f"ad:{rule}")
                else:
                    for raddr in dns_info.get("answers", []):
                        self._register_ad_suspect(mac, raddr, qname)

    def on_tls_hello(self, mac, packet_item, tls_info):
        """TLS SNI 层: DoH服务商阻断(强制降级) + SNI兜底识别(可开关) + 类型阻断."""
        sni = tls_info.get("sni") or ""
        if not sni:
            return
        # 强制降级: 命中公共 DoH 服务商域名 -> 阻断该连接, 迫使设备回落明文DNS
        if self.config.get("force_plain_dns"):
            hit = self.config.match_doh_provider(sni)
            if hit:
                raddr = packet_item["dst"] if packet_item["direction"] == "up" else packet_item["src"]
                log_now, _ = self._hit_once(mac, f"DoH:{hit}")
                if log_now:
                    self.storage.log_event("block", mac, packet_item.get("src", ""),
                                           f"DoH服务商命中: {sni} -> {raddr}")
                self._block_pair(mac, raddr, reason=f"doh:{hit}")
        # SNI 兜底: 域名黑名单 (设备用加密DNS时仍可识别目标域名)
        if (self.config.get("sni_fallback_enabled")
                and (self.config.get("domain_block_enabled")
                     or self.config.get("block_short_video"))):
            hit = self.config.match_domain_blacklist(sni)
            if hit:
                raddr = packet_item["dst"] if packet_item["direction"] == "up" else packet_item["src"]
                log_now, _ = self._hit_once(mac, f"域名:{hit}")
                if log_now:
                    self.storage.log_event("block", mac, packet_item.get("src", ""),
                                           f"SNI黑名单命中: {sni} -> {raddr}")
                self._block_pair(mac, raddr, reason=f"sni:{sni}")
        # 网络净化: 广告SDK SNI (确定性直接拦; 共用域名登记待流量推断)
        if self.config.get("ad_purify_enabled"):
            ad = self.config.match_ad_sdk(sni)
            if ad:
                raddr = packet_item["dst"] if packet_item["direction"] == "up" else packet_item["src"]
                if ad[0] == "definite":
                    log_now, _ = self._hit_once(mac, f"广告:{ad[1]}")
                    if log_now:
                        self.storage.log_event("block", mac, packet_item.get("src", ""),
                                               f"广告SDK SNI命中: {sni} (规则:{ad[1]})")
                    self._block_pair(mac, raddr, reason=f"ad:{ad[1]}")
                else:
                    self._register_ad_suspect(mac, raddr, sni)

    def _hit_once(self, mac, rule, window=60):
        """阻断日志聚合: 同 (设备,规则) 在 window 秒内只报告一次, 其余累计.

        返回 (本次是否报告, 上轮窗口内被抑制的次数). 阻断动作本身不受影响."""
        key = (mac, rule)
        now = time.time()
        with self._lock:
            if len(self._blk_seen) > 512:
                for k in [k for k, v in self._blk_seen.items() if now - v[0] > 600]:
                    self._blk_seen.pop(k, None)
            ent = self._blk_seen.get(key)
            if ent and now - ent[0] < window:
                # 不刷新窗口起点: 持续刷屏时每60秒仍会汇报一次累计数
                ent[1] += 1
                return False, 0
            prev = ent[1] if ent else 0
            self._blk_seen[key] = [now, 0]
        return True, prev

    # ============ 网络净化: 共用域名流量推断 ============

    def _register_ad_suspect(self, mac, raddr, sni):
        """广告/内容共用域名 -> 登记嫌疑, 由 check_ad_suspects 按连接数/流量大小判定."""
        with self._lock:
            if (mac, raddr) not in self._ad_suspect:
                self._ad_suspect[(mac, raddr)] = {
                    "sni": sni, "ts": time.time(), "state": "pending"}

    def check_ad_suspects(self):
        """网络净化推断 (GUI 周期调用).

        共用域名 (pstatp/toutiao/bdstatic 等) 上的连接:
          - 25秒后看该设备->该IP 的连接数与总字节 (活跃流 + 已入库流)
          - 多条连接且总量 < 256KB, 或单连接60秒仍 < 32KB  -> 广告上报, 阻断该IP
          - 持续大流量 -> 正常内容, 放行 (1小时内不重复推断)"""
        if not self.config.get("ad_purify_enabled"):
            return
        now = time.time()
        with self._lock:
            for key in [k for k, v in self._ad_suspect.items()
                        if v["state"] != "pending" and now - v["ts"] > 3600]:
                self._ad_suspect.pop(key, None)
            items = [(k, v) for k, v in self._ad_suspect.items()
                     if v["state"] == "pending"]
        for (mac, raddr), info in items:
            age = now - info["ts"]
            if age < 25:
                continue
            active = [f for f in self.sniffer.get_active_flows(mac)
                      if f["raddr"] == raddr]
            n_conn = len(active)
            total = sum(f["bytes_up"] + f["bytes_down"] for f in active)
            db_n, db_bytes = self.storage.sum_flows_since(mac, raddr, info["ts"])
            n_conn += db_n
            total += db_bytes
            block = False
            if n_conn >= 2 and total < 256 * 1024:
                block = True
            elif n_conn == 1 and total < 32 * 1024 and age > 60:
                block = True
            elif age > 90:
                # 无广告证据 -> 按内容流量放行, 1小时内不再重复推断
                with self._lock:
                    self._ad_suspect[(mac, raddr)] = {
                        "sni": info["sni"], "ts": now, "state": "ok"}
                continue
            else:
                continue
            with self._lock:
                self._ad_suspect.pop((mac, raddr), None)
            self.storage.log_event(
                "block", mac, raddr,
                f"网络净化: {info['sni']} 推断为广告上报 "
                f"({n_conn}条连接/共{total/1024:.0f}KB) -> 阻断 {raddr}")
            self._block_pair(mac, raddr, reason=f"ad-heuristic:{info['sni']}")

    def on_flow_classified(self, mac, raddr, category):
        """流识别完成 -> 类型阻断检查."""
        if not self.config.get("category_block_enabled"):
            return
        blocked = self.config.get("blocked_categories") or []
        if category in blocked:
            self._block_pair(mac, raddr, reason=f"category:{category}")

    def _block_pair(self, mac, raddr, reason=""):
        """记录 目标识别结果 (去重).

        实测: Windows 防火墙对热点转发流量不生效 (NAT转发不过主机过滤点),
        故不再下发按远端IP的防火墙规则; 实际拦截由 DNS 过滤层完成 (解析即拦截)."""
        key = (mac, raddr)
        now = time.time()
        with self._lock:
            if now - self.category_blocks.get(key, 0) < 3600:
                return
            self.category_blocks[key] = now
        c = self.monitor.get_client(mac)
        ip = c.ip if c else ""
        self.storage.log_event("block", mac, ip,
                               f"识别到目标 {raddr} ({reason}); 防火墙对转发流量无效, "
                               f"建议开启DNS过滤从解析层拦截")

    # ============ 周期检查 (由监控线程/GUI after 调用) ============

    def check_quotas(self, rates):
        """rates: sniffer.get_rates() -> 断网名单IP同步 + 配额检查/超限自动断网."""
        self._sync_blocked_ips()          # 周期刷新 mac->IP 映射 (换IP/重连自愈)
        if not self.config.get("quota_auto_block"):
            return
        for mac, r in rates.items():
            st = self.alerts.quota_check(mac, r.get("total_bytes", 0))
            if st == "exceeded" and mac not in self.quota_exceeded:
                with self._lock:
                    self.quota_exceeded.add(mac)
                self.block_internet(mac)
                self._toast("配额", f"{mac} 超配额, 已自动切断外网")

    def set_warn_page(self, enabled):
        """开关闭网警告页: 本机80端口提示页 + 被断网设备 DNS 劫持定向.

        类似 captive portal: Android/iOS 联网检测走明文 HTTP, 会自动弹出
        提示窗口; HTTPS 站点连接失败 (无证书, 不做中间人)."""
        from . import warnpage
        if enabled:
            if not (self.warnpage and self.warnpage.is_alive()):
                wp = warnpage.WarnPageServer(
                    ap_ip_fn=lambda: (self.monitor.ap_iface or {}).get("ip", ""))
                wp.start()
                time.sleep(0.5)
                self.warnpage = wp
                if not wp.bound_ip():
                    self._toast("警告页", "已开启, 但热点未开启或80端口被占用, "
                                "将自动重试绑定")
            # 放行客户端到本机 80 端口 (热点网卡, 幂等)
            try:
                firewall.allow_warn_page()
            except Exception:
                pass
            self._ensure_dnsfilter()
            if self.dnsfilter and self.dnsfilter.is_alive():
                self.dnsfilter.warn_ip_fn = lambda: (
                    self.monitor.ap_iface or {}).get("ip", "")
            self.storage.log_event("control", "", "",
                                   "断网警告页开启: 被断网/踢除设备的HTTP访问"
                                   "劫持到本机提示页 (网关IP:80)")
            self._toast("警告页", "已开启: 被断网设备用浏览器打开任意网址即可看到提示页")
        else:
            if self.dnsfilter and self.dnsfilter.is_alive():
                self.dnsfilter.warn_ip_fn = None
            if self.warnpage:
                self.warnpage.stop()
                self.warnpage = None
            self.storage.log_event("control", "", "", "断网警告页关闭")
            self._toast("警告页", "已关闭: 被断网设备恢复为静默拦截")

    # ============ 弹出指定页面 (captive portal 301 重定向) ============

    def set_portal(self, mac, url):
        """弹出指定页面: 设备重连热点时系统以"网页认证"弹出浏览器窗口,
        301 重定向到管理员指定网址. url 为空 = 取消.

        流程: 记录配置 -> 快速重启热点 (重连触发系统联网探测) -> 设备全部
        DNS 解析劫持到网关 -> 探测/任意HTTP访问落到本机:80 -> 301 到目标.
        HTTPS 站点连接失败 (无证书, 不做中间人), 重定向由 HTTP 层完成."""
        url = str(url or "").strip()
        if url and not url.startswith(("http://", "https://")):
            url = "http://" + url
        if url:
            self.portal_macs[mac] = url
            self.config.set("portal_redirects", dict(self.portal_macs))
            self._ensure_portal_stack()
            self.storage.log_event("control", mac, "",
                                   f"弹出指定页面: {url} (热点快速重启中...)")
            self._toast("弹出页面", f"{mac}: 热点重启后自动弹出 -> {url}")
            threading.Thread(target=self._quick_restart_hotspot,
                             daemon=True).start()
        else:
            old = self.portal_macs.pop(mac, None)
            if not old:
                return "该设备未设置弹出页面"
            self.config.set("portal_redirects", dict(self.portal_macs))
            if not self.portal_macs:
                self._sync_portal_url()     # 最后一个取消 -> 关闭 301 模式
            self._sync_blocked_ips()
            self.storage.log_event("control", mac, "", "取消弹出指定页面")
            self._toast("弹出页面", f"{mac}: 已取消, 设备恢复联网")
        return url or "已取消"

    def _sync_portal_url(self):
        """warnpage.redirect_url 同步 (多设备时用最新设置的网址)."""
        if self.warnpage:
            self.warnpage.redirect_url = ""
            for u in self.portal_macs.values():
                self.warnpage.redirect_url = u
                break

    def _ensure_portal_stack(self):
        """弹页执行层: DNS过滤 + 80端口服务(301模式) + 防火墙放行."""
        self._ensure_dnsfilter()
        if not (self.warnpage and self.warnpage.is_alive()):
            from . import warnpage
            wp = warnpage.WarnPageServer(
                ap_ip_fn=lambda: (self.monitor.ap_iface or {}).get("ip", ""))
            wp.start()
            self.warnpage = wp
            try:
                firewall.allow_warn_page()
            except Exception:
                pass
        self._sync_portal_url()
        if self.dnsfilter and self.dnsfilter.is_alive():
            self.dnsfilter.warn_ip_fn = lambda: (
                self.monitor.ap_iface or {}).get("ip", "")

    def _quick_restart_hotspot(self):
        """快速重启热点 (约10秒): 设备重连触发系统 captive portal 探测."""
        self._toast("热点重启", "热点快速重启中(约10秒), 设备将短暂掉线...")
        try:
            from . import hotspot
            hotspot.stop()
            time.sleep(3)
            hotspot.start()
            try:
                self.sniffer.force_revive(timeout=45)
                self._sync_blocked_ips()
            except Exception:
                pass
            self.storage.log_event("control", "", "",
                                   "热点快速重启完成: 目标设备重连后弹出指定页面")
            self._toast("热点重启", "热点已重启; 目标设备重连后自动弹出指定页面")
        except Exception as e:
            self.storage.log_event("control", "", "", f"热点快速重启失败: {e}")
            self._toast("热点重启", f"重启失败: {e}; 请手动开关热点")

    def restore_portals(self):
        """程序启动恢复: 上次会话的弹出页面配置 (不重启热点, 设备重连时生效)."""
        saved = self.config.get("portal_redirects") or {}
        if isinstance(saved, dict) and saved:
            self.portal_macs = dict(saved)
            self._ensure_portal_stack()
            self._sync_blocked_ips()
            self.storage.log_event("control", "", "",
                                   f"恢复弹出页面配置: {len(saved)} 台设备")

    def cleanup(self):
        if self.netkill:
            try:
                self.netkill.stop()
            except Exception:
                pass
        if self.warnpage:
            try:
                self.warnpage.stop()
            except Exception:
                pass
        firewall.cleanup_all_rules()
