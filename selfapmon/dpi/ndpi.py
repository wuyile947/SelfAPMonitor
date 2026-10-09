"""可选 nDPI 集成 (Windows libndpi.dll, ctypes 动态加载).

定位: 增强识别精度, 非必需。dll 缺失/ABI 不兼容时自动退回启发式。
搜索路径: config.ndpi_dll_path -> ./bin/libndpi*.dll -> PATH 中的 libndpi*.dll

nDPI (ntop, LGPLv3) Windows 构建方式 (见 docs/INSTALL.md):
    MSYS2: pacman -S mingw-w64-x86_64-ndpi
    拷贝 C:\\msys64\\mingw64\\bin\\libndpi-*.dll 到本项目 bin\\ 目录

兼容目标: nDPI 4.x ABI
  ndpi_init_detection_module / ndpi_finalize_initialization
  ndpi_detection_process_packet(mod, flow, ip_packet, len, tick, input_info)
  ndpi_detection_giveup(mod, flow, enable_guess)
  ndpi_get_proto_name / ndpi_category_get_name

安全设计:
  - ndpi_protocol 结构体按 64 字节声明(实际更小), 避免返回值缓冲区越界
  - 所有调用包在 try/except; Windows 上 ctypes 会把原生访问违例转为可捕获异常
  - 任一异常 => 永久禁用 nDPI 后端, 自动退回启发式识别
  - 本模块不解密任何内容, 仅喂给 nDPI 原始 IP 包字节做协议指纹识别
"""
import ctypes
import os

from .. import app_root


def _search_paths():
    root = app_root()
    return [
        os.path.join(root, "bin", "libndpi.dll"),
        os.path.join(root, "bin", "ndpi.dll"),
        os.path.join(root, "bin", "libndpi-6.dll"),
        os.path.join(root, "bin", "libndpi-5.dll"),
        os.path.join(root, "bin", "libndpi-4.dll"),
    ]

# nDPI 类别名 -> 本项目类别
_CATEGORY_MAP = {
    "Media": "Video", "Streaming": "Video", "Video": "Video", "Music": "Video",
    "Web": "Text", "SocialNetwork": "Text", "Chat": "Text", "Mail": "Text",
    "Download": "Download", "Download-FileTransfer-FileSharing": "Download",
    "FileTransfer": "Download", "P2P": "Download",
    "Game": "Game",
    "VoIP": "VoIP",
}

# 声明为 64 字节大结构 (nDPI 4.x 实际 ~12-40 字节, 声明偏大是安全的:
# Windows x64 上 >8 字节结构经隐藏指针返回, 调用方缓冲区必须 >= 真实大小)
class _NdpiProtocol(ctypes.Structure):
    _fields_ = [
        ("master_protocol", ctypes.c_uint16),
        ("app_protocol", ctypes.c_uint16),
        ("category", ctypes.c_int32),
        ("breed", ctypes.c_int32),
        ("pad", ctypes.c_ubyte * 48),
    ]


class _NdpiFlowInputInfo(ctypes.Structure):
    """nDPI 4.x ndpi_flow_input_info (声明 16 字节, 偏大安全)."""
    _fields_ = [
        ("is_ipv6", ctypes.c_uint8),
        ("is_dns", ctypes.c_uint8),
        ("is_tls", ctypes.c_uint8),
        ("is_udp", ctypes.c_uint8),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("pad", ctypes.c_ubyte * 8),
    ]


class NdpiEngine:
    def __init__(self, config=None):
        self.lib = None
        self.mod = None
        self.version = ""
        self.sizeof_flow = 0
        self.available = False
        self._flows = {}   # key -> dict(buf, fed, result, giveup)
        try:
            self._load(config)
        except Exception:
            self.available = False

    # ---------- 加载 ----------
    def _find_dll(self, config=None):
        candidates = []
        if config is not None:
            try:
                custom = config.get("ndpi_dll_path")
                if custom:
                    candidates.append(custom)
            except Exception:
                pass
        candidates.extend(_search_paths())
        for c in candidates:
            if c and os.path.exists(c):
                return c
        for d in os.environ.get("PATH", "").split(os.pathsep):
            if not d:
                continue
            for name in ("libndpi.dll", "ndpi.dll"):
                p = os.path.join(d.strip('" '), name)
                if os.path.exists(p):
                    return p
        return None

    def _load(self, config=None):
        path = self._find_dll(config)
        if not path:
            return
        try:
            for extra in ("bin", os.path.dirname(os.path.abspath(path))):
                try:
                    os.add_dll_directory(os.path.abspath(extra))
                except Exception:
                    pass
            lib = ctypes.CDLL(path)
        except OSError:
            return
        self.lib = lib

        try:
            lib.ndpi_get_version.restype = ctypes.c_char_p
            self.version = lib.ndpi_get_version().decode("ascii", "replace")
        except Exception:
            self.version = "nDPI?"

        try:
            lib.ndpi_detection_get_sizeof_ndpi_flow_struct.restype = ctypes.c_size_t
            self.sizeof_flow = lib.ndpi_detection_get_sizeof_ndpi_flow_struct()
        except Exception:
            return
        if not (1024 < self.sizeof_flow < 65536):
            return

        try:
            lib.ndpi_init_detection_module.restype = ctypes.c_void_p
            mod = lib.ndpi_init_detection_module()
            if not mod:
                return
            self.mod = ctypes.c_void_p(mod)
            try:
                lib.ndpi_finalize_initialization.argtypes = [ctypes.c_void_p]
                lib.ndpi_finalize_initialization(self.mod)
            except Exception:
                pass

            lib.ndpi_get_proto_name.restype = ctypes.c_char_p
            lib.ndpi_get_proto_name.argtypes = [ctypes.c_void_p, ctypes.c_uint16]
            lib.ndpi_category_get_name.restype = ctypes.c_char_p
            lib.ndpi_category_get_name.argtypes = [ctypes.c_void_p, ctypes.c_int]

            lib.ndpi_detection_process_packet.restype = _NdpiProtocol
            lib.ndpi_detection_process_packet.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p,
                ctypes.c_uint16, ctypes.c_uint64, ctypes.c_void_p]
            try:
                lib.ndpi_detection_giveup.restype = _NdpiProtocol
                lib.ndpi_detection_giveup.argtypes = [
                    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
            except Exception:
                pass
            self.available = True
        except Exception:
            self.available = False

    # ---------- 分类 ----------
    def _flow(self, key):
        f = self._flows.get(key)
        if f is None:
            f = {"buf": ctypes.create_string_buffer(self.sizeof_flow),
                 "fed": 0, "result": None, "closed": False}
            self._flows[key] = f
        return f

    def classify(self, key, packets):
        """packets: list[dict(proto,sport,dport,payload,ip_bytes)]

        返回 (proto_name|None, category|None). 仅喂原始 IP 包字节(明文指纹).
        """
        if not self.available or not self.mod or not packets:
            return None, None
        f = self._flow(key)
        if f["closed"] and f["result"]:
            return f["result"]
        lib = self.lib
        try:
            for p in packets[f["fed"]:20]:
                ipb = p.get("ip_bytes")
                if not ipb or len(ipb) > 65535:
                    continue
                info = _NdpiFlowInputInfo(
                    is_ipv6=0,
                    is_dns=1 if p.get("proto") == 17 and 53 in (p.get("sport"), p.get("dport")) else 0,
                    is_tls=0, is_udp=1 if p.get("proto") == 17 else 0,
                    src_port=p.get("sport") or 0, dst_port=p.get("dport") or 0)
                ret = lib.ndpi_detection_process_packet(
                    self.mod, f["buf"], ipb, ctypes.c_uint16(len(ipb)),
                    ctypes.c_uint64(0), ctypes.byref(info))
                f["fed"] += 1
                if ret and (ret.master_protocol or ret.app_protocol):
                    name_id = ret.master_protocol or ret.app_protocol
                    pname = lib.ndpi_get_proto_name(self.mod, name_id).decode("ascii", "replace")
                    cat_name = ""
                    try:
                        cat_name = lib.ndpi_category_get_name(self.mod, int(ret.category)).decode("ascii", "replace")
                    except Exception:
                        pass
                    if pname and pname != "Unknown":
                        cat = _CATEGORY_MAP.get(cat_name, None)
                        f["result"] = (pname, cat)
                        f["closed"] = True
                        return f["result"]
            # 喂了若干包仍无结果 -> giveup 猜测
            if f["fed"] >= min(10, len(packets)) and not f["closed"]:
                try:
                    ret = lib.ndpi_detection_giveup(self.mod, f["buf"], 1)
                    if ret:
                        name_id = ret.master_protocol or ret.app_protocol
                        if name_id:
                            pname = lib.ndpi_get_proto_name(self.mod, name_id).decode("ascii", "replace")
                            cat_name = ""
                            try:
                                cat_name = lib.ndpi_category_get_name(self.mod, int(ret.category)).decode("ascii", "replace")
                            except Exception:
                                pass
                            if pname and pname != "Unknown":
                                f["result"] = (pname, _CATEGORY_MAP.get(cat_name))
                except Exception:
                    pass
                f["closed"] = True
            return f["result"] if f["result"] else (None, None)
        except Exception:
            # 任何异常 => 禁用 nDPI, 退回启发式
            self.available = False
            try:
                self.mod = None
            except Exception:
                pass
            return None, None

    def info(self):
        return f"nDPI {self.version}" if self.available else "unavailable"
