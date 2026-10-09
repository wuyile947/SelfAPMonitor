"""JSON 配置加载/保存. 默认配置 -> 用户修改后持久化到 data/config.json."""
import json
import os

from . import app_root

CONFIG_DIR = os.path.join(app_root(), "data")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")

DEFAULTS = {
    # ---- 热点 ----
    "hotspot_ssid": "SelfAPMon-Hotspot",
    "hotspot_password": "",           # 8-63 位; 空则不修改
    "hotspot_band": "Auto",           # Auto / WiFi24GHz / WiFi50GHz
    "max_clients": 8,
    # ---- 网卡/接口 (留空自动探测) ----
    "ap_interface_alias": "",         # 热点虚拟网卡别名, 如 "本地连接* 3"
    # ---- 采集 ----
    "sniff_enabled": True,
    "known_devices": [],              # 白名单 MAC 列表 (小写)
    "blacklist_macs": [],             # 黑名单 MAC: 自动断网+告警
    "device_aliases": {},             # mac -> 设备别名 (如 "爸爸的手机")
    # ---- 告警阈值 ----
    "rate_spike_bps": 5 * 1024 * 1024,   # 单设备下行突增阈值 5 MB/s
    "spike_windows": 3,                  # 连续 N 个采样超阈值才告警
    "alert_cooldown_sec": 300,           # 同类告警冷却
    # ---- 配额 (mac -> MB) ----
    "quota_mb": {},
    "quota_auto_block": True,            # 超配额自动断外网
    # ---- 域名黑名单 ----
    "domain_blacklist": [],              # 例: ["*.example.com", "badsite.cn"]
    "domain_block_enabled": True,
    "block_short_video": True,           # 内置短视频域名屏蔽 (抖音/快手/微视等)
    "ad_purify_enabled": True,           # 网络净化: 拦截穿山甲/优量汇等广告SDK
    "dns_filter_enabled": False,         # DNS过滤: 热点网关:53 解析拦截 (域名黑名单/设备断网执行层)
    "force_plain_dns": False,            # 强制降级: 阻断853/DoH服务商, 可能断网
    "sni_fallback_enabled": True,        # 提取SNI兜底识别域名 (加密DNS时)
    "conn_kill_enabled": True,           # 连接层阻断: 命中黑名单/短视频的连接注入RST/QUIC VN (补HTTPDNS绕过, 主动发包)
    "arp_kill_enabled": True,            # ARP断流: 对断网设备伪造ARP应答切断上行, 杀已建立QUIC连接 (主动发包)
    "portal_redirects": {},              # 弹出指定页面: {mac: url} 重连热点时captive portal 301跳转
    "blackhole_pulse_sec": 45,           # 脉冲黑洞: 命中黑名单时短时黑洞存量连接池, 到期自动撤销 (0=禁用脉冲)
    "warn_page_enabled": False,          # 断网警告页: 被断网设备DNS劫持到本机80端口提示页
    "hard_kill_stop_sec": 5,             # 彻底断网热点停机秒数: 杀死既有连接即可, 重连后ARP断流/DNS/RST自动接上
    # ---- 类型阻断 (按识别类别) ----
    "blocked_categories": [],            # 例: ["Video", "Download", "Game"]
    "category_block_enabled": False,
    # ---- 存储/轮转 ----
    "db_retention_days": 14,
    "db_max_mb": 200,                    # 超过后清理最旧明细并 VACUUM
    # ---- DPI ----
    "ndpi_dll_path": "",                 # 留空自动搜索; 否则指定 libndpi.dll 路径
    # ---- 界面 ----
    "ui_refresh_ms": 1000,
}


# 内置短视频 App 域名 (抖音/快手/微视等; 精确规则自动覆盖其全部子域).
# 仅作为 DNS/SNI 域名层的阻断规则, 不涉及任何内容解析.
SHORT_VIDEO_DOMAINS = [
    # 抖音 / 字节系
    "douyin.com", "douyinpic.com", "douyincdn.com", "douyinstatic.com",
    "douyinvod.com", "amemv.com", "snssdk.com", "zjcdn.com", "bytecdn.cn",
    "pipix.com", "ixigua.com", "huoshan.com",
    # 快手
    "kuaishou.com", "gifshow.com", "ksapisrv.com", "kwimgs.com", "yximgs.com",
    "chenzhongtech.com",
    # 腾讯微视
    "weishi.qq.com",
]

# 短视频关键字: 域名"包含"即命中 (比后缀匹配更严, 兼容 .mshome.net 等被改写尾缀的域名).
# 覆盖两家的 API/CDN/HTTPDNS 引导域名, 命中后其 HTTPDNS 引导也失败 -> 回落系统DNS仍被拦.
SHORT_VIDEO_KEYWORDS = (
    # 抖音/字节系
    "douyin", "amemv", "snssdk", "ixigua", "huoshan", "pipix", "zjcdn",
    # 快手系
    "kuaishou", "gifshow", "ksapisrv", "kwimgs", "yximgs", "chenzhongtech",
)

# 常见公共 DoH/DoT 服务商域名 (强制降级开启时, 命中即阻断, 迫使设备回落明文DNS)
DOH_PROVIDER_DOMAINS = [
    "dns.google", "cloudflare-dns.com", "one.one.one.one", "dns.quad9.net",
    "doh.pub", "dns.alidns.com", "dot.pub", "doh.360.cn", "doh.opendns.com",
    "dns.adguard.com",
]

# 网络净化: 确定性广告SDK域名 (只被广告/SDK使用, 命中 DNS/SNI 即阻断该连接IP).
AD_SDK_DOMAINS = [
    # 穿山甲 (字节跳动联盟)
    "pangolin-sdk-toutiao.com", "pangolin.snssdk.com", "pangle.cn", "pangle.io",
    "ad.toutiao.com", "dsp.toutiao.com", "is.snssdk.com",
    # 优量汇 (腾讯联盟) / 腾讯SDK
    "gdt.qq.com", "gdtimg.com", "ugdtimg.com", "e.qq.com", "adsmind.qq.com",
    # 百度SSP/百度统计
    "mobads.baidu.com", "mobads-logs.baidu.com", "pos.baidu.com", "cpro.baidu.com",
    "eclick.baidu.com", "duclick.baidu.com", "hmma.baidu.com",
    # 快手联盟
    "ksadx.com", "ad.kuaishou.com",
    # 友盟+ (统计/推送)
    "umeng.com", "umengcloud.com",
    # Google 广告/统计
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "app-measurement.com", "crashlytics.com",
    # 其他主流广告联盟
    "unityads.unity3d.com", "app.unitychina.cn", "mintegral.com", "mobvista.com",
    "applovin.com", "vungle.com", "tapjoy.com", "ironsrc.com",
]

# 网络净化: 广告与内容共用的域名 (不能见一个拦一个, 由 control 按连接数/流量大小推断:
# 多条短连接且总量极小 = 广告上报 -> 阻断该IP; 持续大流量 = 正常内容 -> 放行).
AD_SHARED_DOMAINS = [
    "pstatp.com",     # 字节CDN: 头条/抖音内容 与 穿山甲广告素材 共用
    "toutiao.com",    # 今日头条内容 与 广告请求 共用
    "bdstatic.com",   # 百度静态资源 与 广告素材 共用
]


class Config:
    def __init__(self):
        self._data = dict(DEFAULTS)
        self.load()

    def load(self):
        try:
            if os.path.exists(CONFIG_PATH):
                with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                    user = json.load(f)
                for k, v in user.items():
                    if k in DEFAULTS:
                        self._data[k] = v
        except Exception:
            pass
        # 规范化 MAC
        self._data["known_devices"] = [self._norm_mac(m) for m in self._data["known_devices"]]
        self._data["blacklist_macs"] = [self._norm_mac(m) for m in self._data["blacklist_macs"]]
        self._data["quota_mb"] = {self._norm_mac(m): v for m, v in self._data["quota_mb"].items()}
        self._data["domain_blacklist"] = [d.strip().lower() for d in self._data["domain_blacklist"] if d.strip()]

    def save(self):
        try:
            os.makedirs(CONFIG_DIR, exist_ok=True)
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(self._data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def get(self, key):
        return self._data.get(key, DEFAULTS.get(key))

    def set(self, key, value, persist=True):
        self._data[key] = value
        if persist:
            self.save()

    # ---- 便捷方法 ----
    @staticmethod
    def _norm_mac(mac):
        return str(mac).strip().lower().replace("-", ":")

    def is_whitelisted(self, mac):
        return self._norm_mac(mac) in self._data["known_devices"]

    def is_blacklisted(self, mac):
        return self._norm_mac(mac) in self._data["blacklist_macs"]

    def add_whitelist(self, mac):
        mac = self._norm_mac(mac)
        if mac and mac not in self._data["known_devices"]:
            self._data["known_devices"].append(mac)
            self.save()

    def remove_whitelist(self, mac):
        mac = self._norm_mac(mac)
        if mac in self._data["known_devices"]:
            self._data["known_devices"].remove(mac)
            self.save()

    def add_blacklist(self, mac):
        mac = self._norm_mac(mac)
        if mac and mac not in self._data["blacklist_macs"]:
            self._data["blacklist_macs"].append(mac)
            self.save()

    def remove_blacklist(self, mac):
        mac = self._norm_mac(mac)
        if mac in self._data["blacklist_macs"]:
            self._data["blacklist_macs"].remove(mac)
            self.save()

    def set_quota(self, mac, mb):
        self._data["quota_mb"][self._norm_mac(mac)] = float(mb)
        self.save()

    def clear_quota(self, mac):
        self._data["quota_mb"].pop(self._norm_mac(mac), None)
        self.save()

    def get_quota_mb(self, mac):
        return self._data["quota_mb"].get(self._norm_mac(mac))

    # ---- 设备别名 ----
    def get_alias(self, mac):
        return self._data["device_aliases"].get(self._norm_mac(mac), "")

    def set_alias(self, mac, alias):
        mac = self._norm_mac(mac)
        alias = str(alias).strip()
        if not alias:
            self._data["device_aliases"].pop(mac, None)
        else:
            self._data["device_aliases"][mac] = alias
        self.save()

    def match_domain_blacklist(self, domain):
        """domain 大小写不敏感; 精确匹配同时覆盖其子域; 支持 *.xxx.com 通配.
        命中用户黑名单返回规则; 命中内置短视频清单返回 规则+"(内置)"."""
        if not domain:
            return None
        d = str(domain).lower().rstrip(".")
        hit = self._match_patterns(self._data["domain_blacklist"], d)
        if hit:
            return hit
        if self._data.get("block_short_video"):
            hit = self._match_patterns(SHORT_VIDEO_DOMAINS, d)
            if hit:
                return hit + "(内置)"
            # 关键字包含匹配: 域名任意位置含抖音等关键字即拦截
            for kw in SHORT_VIDEO_KEYWORDS:
                if kw in d:
                    return kw + "*(内置)"
        return None

    @staticmethod
    def _match_patterns(pats, d):
        for pat in pats:
            if pat.startswith("*."):
                base = pat[2:]
                if d == base or d.endswith("." + base):
                    return pat
            elif d == pat or d.endswith("." + pat):
                return pat
        return None

    def match_doh_provider(self, domain):
        """命中公共 DoH/DoT 服务商域名则返回规则 (强制降级用)."""
        if not domain:
            return None
        return self._match_patterns(DOH_PROVIDER_DOMAINS, str(domain).lower().rstrip("."))

    def match_ad_sdk(self, domain):
        """网络净化匹配: ("definite", 规则)=确定广告域名 / ("shared", 规则)=共用域名 / None."""
        if not domain:
            return None
        d = str(domain).lower().rstrip(".")
        hit = self._match_patterns(AD_SDK_DOMAINS, d)
        if hit:
            return ("definite", hit)
        hit = self._match_patterns(AD_SHARED_DOMAINS, d)
        if hit:
            return ("shared", hit)
        return None
