"""启发式流量分类器 (无解密, 仅端口/明文握手特征).

类别: Video(视频) Text(文本/网页) Download(下载) Game(游戏) Web DNS VoIP P2P Unknown
不涉及任何加密内容解析。
"""
import re
from collections import Counter

CATEGORY_NAMES = ["Video", "Text", "Download", "Game", "Web", "DNS", "VoIP", "P2P", "Unknown"]

# SNI 域名关键词 -> 类别 (小写匹配)
_SNI_RULES = [
    # 视频
    (r"(youtube|ytimg|googlevideo)\.", "Video"),
    (r"(netflix|nflx(video|img)?\.)", "Video"),
    (r"(bilibili|hdslb|bvc)\.", "Video"),
    (r"(douyin|tiktok|bytedance|bytecdn|zjcdn|ixigua)\.", "Video"),
    (r"(iqiyi|qy\.net|qy\.com|douyu|huya)\.", "Video"),
    (r"(kuaishou|gifshow|ksapisrv)\.", "Video"),
    (r"(tencentvideo|qq\.com/video|v\.qq\.com)", "Video"),
    (r"(youku|alibaba.*video|miguvideo|acfun)\.", "Video"),
    (r"(twitch\.tv|ttvnw\.net|dailymotion|vimeo)\.", "Video"),
    (r"(bds\.video|akamaized\.net|video.*\.cdn)", "Video"),
    (r"(pornhub|xvideos|xhamster)", "Video"),
    # 游戏
    (r"(steampowered|steamcontent|steamstatic)\.", "Game"),
    (r"(epicgames|unrealengine)\.", "Game"),
    (r"(riotgames|leagueoflegends|valorant)\.", "Game"),
    (r"(battle\.net|blizzard|battlenet)\.", "Game"),
    (r"(ea\.com|origin\.com|eac-cdn)\.", "Game"),
    (r"(ubisoft|uplay)\.", "Game"),
    (r"(mojang|minecraft)\.", "Game"),
    (r"(roblox|riotcdn|wildrift)\.", "Game"),
    (r"(miHoYo|hoyoverse|mihoyo|yuanshen|zenless)\.", "Game"),
    (r"(tencentgames|pubg|peaceelite)\.", "Game"),
    (r"(nintendo|playstation|xbox.*live|xboxlive)\.", "Game"),
    # 下载
    (r"(download.*\.|\.download\.)", "Download"),
    (r"(cdn\.dl|dl\.cdn|releases\.)", "Download"),
    (r"(msedge\.windowsupdate|windowsupdate\.com)", "Download"),
    (r"(d\.cdn\.|file.*cdn|download\.)", "Download"),
    (r"(speedtest|ooklaserver)", "Download"),
    (r"(apk\-?pure|appstore|itunes\.apple)", "Download"),
    # 文本/网页
    (r"(google|gstatic|googleapis)\.", "Text"),
    (r"(facebook|instagram|whatsapp|fbcdn)\.", "Text"),
    (r"(twitter|x\.com|twimg)\.", "Text"),
    (r"(baidu|bdstatic|bdimg)\.", "Text"),
    (r"(taobao|tbcdn|tmall|aliyun)\.", "Text"),
    (r"(qq\.com|weixin|wechat|gtimg)\.", "Text"),
    (r"(163\.com|126\.net|netease)\.", "Text"),
    (r"(sohu|sogou|360\.com|qihoo)\.", "Text"),
    (r"(zhihu|weibo|xiaohongshu|sinaimg)\.", "Text"),
    (r"(wikipedia|wikimedia)\.", "Text"),
    (r"(openai|anthropic|claude\.ai|chatgpt)\.", "Text"),
    (r"(microsoft|msn\.com|bing\.com|live\.com)\.", "Text"),
    (r"(github|gitlab|stackoverflow)\.", "Text"),
]

_SNI_RE = [(re.compile(p), c) for p, c in _SNI_RULES]

# 端口特征
PORT_TCP = {
    80: "Web", 8080: "Web", 8000: "Web", 8888: "Web",
    443: "Text",              # TLS 默认文本/网页, SNI 可提升为其他类
    21: "Download", 69: "Download",
    1935: "Video",            # RTMP
    6667: "Text",
    6881: "P2P", 6882: "P2P", 6883: "P2P", 6889: "P2P", 16881: "P2P",
    25565: "Game",            # Minecraft
    27015: "Game", 27016: "Game", 27017: "Game", 27018: "Game", 27030: "Game",
    3724: "Game",             # WoW
    5222: "Text",
}
PORT_UDP = {
    53: "DNS",
    443: "Text",              # QUIC
    3478: "VoIP", 3479: "VoIP", 5349: "VoIP",   # STUN/TURN
    5060: "VoIP", 5061: "VoIP",
    19302: "VoIP",            # Google STUN
    8000: "VoIP",             # WeChat voice 常见
    3074: "Game", 3075: "Game", 3074 + 1000: "Game",  # Xbox Live 3074
    27015: "Game", 27016: "Game", 27017: "Game", 27018: "Game", 27020: "Game",
    7777: "Game", 7778: "Game",
    51820: "Text",            # WireGuard
    1194: "Text",             # OpenVPN
}

# 明文载荷特征 (首包/前几包)
_SIGNATURES = [
    (b"GET ", "Web", "http-get"),
    (b"POST ", "Web", "http-post"),
    (b"HTTP/1.", "Web", "http-resp"),
    (b"\x16\x03\x01", "Text", "tls12"),
    (b"\x16\x03\x03", "Text", "tls13"),
    (b"\x03", "Video", "rtmp-handshake"),      # RTMP C0/C1 首字节 0x03 (谨慎)
    (b"BitTorrent protocol", "P2P", "bittorrent"),
    (b"\x13BitTorrent", "P2P", "bittorrent"),
    (b"Q0", "Text", "quic"),
]


class HeuristicClassifier:
    def __init__(self):
        self.flow_cache = {}  # key -> (category, detail)

    # ---- SNI 识别 ----
    def classify_sni(self, sni):
        if not sni:
            return None
        sni = sni.lower()
        for rx, cat in _SNI_RE:
            if rx.search(sni):
                return cat
        return None

    def classify(self, packets):
        """packets: list of {proto:int, sport:int, dport:int, payload:bytes|None}
        返回 (category, detail)."""
        if not packets:
            return "Unknown", "no-packet"
        p0 = packets[0]
        proto = p0.get("proto", 0)
        sport, dport = p0.get("sport", 0), p0.get("dport", 0)

        # DNS
        if proto == 17 and (sport == 53 or dport == 53):
            return "DNS", "udp/53"
        if proto == 6 and (sport == 53 or dport == 53):
            return "DNS", "tcp/53"

        # 端口表 (客户端视角: dport 是远端端口)
        remote_port = dport if dport != 0 else sport
        table = PORT_TCP if proto == 6 else PORT_UDP if proto == 17 else {}
        port_cat = table.get(remote_port)
        if port_cat is None:
            port_cat = table.get(sport)

        # 载荷特征
        payload = b""
        for p in packets[:6]:
            pl = p.get("payload")
            if pl:
                payload += pl[:256]
            if len(payload) > 512:
                break
        sig_cat, sig_name = None, ""
        for sig, cat, name in _SIGNATURES:
            if payload.startswith(sig) or (sig in payload[:128] and len(sig) > 2):
                sig_cat, sig_name = cat, name
                break

        if sig_cat == "P2P":
            return "P2P", sig_name
        if port_cat == "P2P":
            return "P2P", f"port/{remote_port}"
        if sig_cat and sig_cat != "Video" and sig_cat != "Text":
            return sig_cat, sig_name
        if port_cat == "VoIP" or sig_cat == "VoIP":
            return "VoIP", f"port/{remote_port}"

        # TLS 443: 看 SNI (已在 classify_sni 中处理, 由 DpiEngine 传入)
        if port_cat == "Game":
            return "Game", f"port/{remote_port}"
        if sig_cat == "Video":
            return "Video", sig_name
        if port_cat == "Video":
            return "Video", f"port/{remote_port}"

        if proto == 17 and remote_port in (443,):
            # QUIC 无法读明文, 按端口保守归类
            return "Text", "quic/443"

        if port_cat in ("Web", "Text", "Download"):
            return port_cat, f"port/{remote_port}"

        # 未知高位端口 + UDP 大包 -> 可能游戏/语音
        if proto == 17 and remote_port > 10000:
            return "Unknown", f"udp/{remote_port}"
        if proto == 6 and payload.startswith((b"GET", b"POST", b"HTTP")):
            return "Web", "http-plain"
        return "Unknown", f"{'tcp' if proto == 6 else 'other'}/{remote_port}"
