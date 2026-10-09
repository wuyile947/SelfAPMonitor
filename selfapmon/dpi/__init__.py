"""DPI 识别: 启发式分类器 + 可选 nDPI (Windows libndpi.dll)."""
from .base import HeuristicClassifier, CATEGORY_NAMES
from .ndpi import NdpiEngine


class DpiEngine:
    """统一入口: 优先 nDPI (如果 dll 可用), 否则启发式; 结果统一为类别."""

    def __init__(self, config=None):
        self.config = config
        self.backend = "heuristic"
        self._ndpi = None
        try:
            nd = NdpiEngine(config)
            if nd.available:
                self._ndpi = nd
                self.backend = "nDPI (" + nd.version + ")"
        except Exception:
            self._ndpi = None
        self._heuristic = HeuristicClassifier()

    def classify_flow(self, key, packets):
        """key: tuple, packets: list[dict(proto, sport, dport, payload(bytes or None), sni)]

        返回 (category:str, detail:str)  如 ("Video", "bilibili.com/tls")
        """
        # 1) SNI 关键词优先 (对 HTTPS 流量最有效的无解密手段)
        sni = next((p.get("sni") for p in packets if p.get("sni")), None)
        cat_from_sni = self._heuristic.classify_sni(sni) if sni else None

        # 2) nDPI
        if self._ndpi is not None:
            try:
                proto_name, category = self._ndpi.classify(key, packets)
                if category:
                    return category, f"{proto_name}" + (f"/{sni}" if sni else "")
            except Exception:
                pass

        # 3) 启发式 (端口/载荷特征)
        cat, detail = self._heuristic.classify(packets)
        # SNI 识别到的类别优先于 端口推断的通用 Web/Text 类
        if cat_from_sni and cat in ("Web", "Text", "Unknown"):
            return cat_from_sni, detail + (f" sni={sni}" if sni else "")
        return cat, detail + (f" sni={sni}" if sni else "")

    def info(self):
        return self.backend
