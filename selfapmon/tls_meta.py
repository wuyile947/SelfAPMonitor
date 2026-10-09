"""DNS / TLS 握手元数据解析 (仅明文字段, 不解密任何内容).

DNS:  解析查询名/查询类型/应答A记录 (手动解析, 不依赖抓包库)
TLS:  解析 ClientHello 明文字段: 版本/SNI/ALPN/JA3,
      并检测 ESNI(0xFFCE) / ECH(0xFE0D,0xFE03) 扩展 -> 标记"加密SNI"
      ECH 场景下外部观察者看不到真实 SNI, 我们只记录"使用了ECH"这一事实。

一切输出均为元数据, 用于流量类型观测与本地管控决策。
"""
import hashlib

# 本项目流量类别 (gui/管控共用)
CATEGORY_LIST = ["Video", "Text", "Download", "Game", "Web", "DNS", "VoIP", "P2P", "Unknown"]

# ---- DNS ----

_DNS_TYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
                   16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}


def parse_dns(data: bytes):
    """解析 DNS 查询/应答. 返回 dict 或 None.

    返回字段: qname, qtype(名称), is_response, answers([ip,...]), https_rr(bool)
    https_rr=True 表示查询/应答包含 HTTPS(65) 记录 -> 客户端可能使用 ECH
    """
    try:
        if len(data) < 12:
            return None
        tid, flags, qd, an, ns, ar = struct_unpack6(data)
        is_response = bool(flags & 0x8000)
        off = 12

        def read_name(off):
            labels = []
            jumped = False
            end = off
            seen = 0
            while True:
                if off >= len(data) or seen > 64:
                    break
                l = data[off]
                if l == 0:
                    if not jumped:
                        end = off + 1
                    break
                if l & 0xC0 == 0xC0:
                    if off + 1 >= len(data):
                        break
                    ptr = ((l & 0x3F) << 8) | data[off + 1]
                    if not jumped:
                        end = off + 2
                    off = ptr
                    jumped = True
                    seen += 1
                    continue
                labels.append(data[off + 1: off + 1 + l].decode("ascii", "replace"))
                off += 1 + l
                if not jumped:
                    end = off
            return ".".join(x for x in labels if x), end

        qname, qtype = "", 0
        if qd:
            qname, off2 = read_name(off)
            if off2 + 4 <= len(data):
                qtype = (data[off2] << 8) | data[off2 + 1]
            off = off2 + 4

        answers = []
        https_rr = (qtype == 65)
        rrcount = an if is_response else 0
        for _ in range(min(rrcount, 32)):
            _, off2 = read_name(off)
            if off2 + 10 > len(data):
                break
            rtype = (data[off2] << 8) | data[off2 + 1]
            rdlen = (data[off2 + 8] << 8) | data[off2 + 9]
            rd = data[off2 + 10: off2 + 10 + rdlen]
            if rtype == 1 and len(rd) == 4:
                answers.append(".".join(str(b) for b in rd))
            elif rtype == 28 and len(rd) == 16:
                try:
                    import socket
                    answers.append(socket.inet_ntop(socket.AF_INET6, rd))
                except Exception:
                    pass
            if rtype == 65:
                https_rr = True
            off = off2 + 10 + rdlen
        if not is_response and ar >= 1:
            # OPT(EDNS) 跳过即可
            pass
        return {
            "qname": qname,
            "qtype": _DNS_TYPE_NAMES.get(qtype, str(qtype)),
            "is_response": is_response,
            "answers": answers,
            "https_rr": https_rr,
            "id": tid,
        }
    except Exception:
        return None


def struct_unpack6(data):
    import struct
    return struct.unpack(">HHHHHH", data[:12])


# ---- TLS ClientHello ----

def parse_tls_client_hello(data: bytes):
    """解析 TLS ClientHello (首记录).

    返回 dict 或 None:
      tls_version, sni, alpn[], ja3, esni(bool), ech(bool), ciphers_count
    仅读取明文字段; ECH 加密部分(outer SNI 等)不解析不解密。
    """
    try:
        if len(data) < 5:
            return None
        ctype = data[0]
        if ctype != 0x16:  # handshake
            return None
        # record: type(1) ver(2) len(2)
        ver = (data[1] << 8) | data[2]
        reclen = (data[3] << 8) | data[4]
        body = data[5: 5 + reclen]
        if len(body) < 4:
            return None
        htype = body[0]
        if htype != 0x01:  # client hello
            return None
        # handshake header: type(1) len(3)
        p = 4
        if p + 34 > len(body):
            return None
        client_ver = (body[p] << 8) | body[p + 1]
        p += 2
        p += 32  # random
        sid_len = (body[p] << 8) | body[p + 1]
        p += 2 + sid_len
        if p + 2 > len(body):
            return None
        cs_len = (body[p] << 8) | body[p + 1]
        p += 2
        ciphers = []
        n = cs_len // 2
        for i in range(min(n, 200)):
            if p + 2 * i + 1 < len(body):
                ciphers.append((body[p + 2 * i] << 8) | body[p + 2 * i + 1])
        p += cs_len
        if p >= len(body):
            return None
        comp_len = body[p]
        p += 1 + comp_len
        if p + 2 > len(body):
            exts = []
        else:
            ext_len = (body[p] << 8) | body[p + 1]
            p += 2
            ext_end = min(p + ext_len, len(body))
            exts = _parse_extensions(body[p:ext_end])

        sni = exts.get("sni")
        alpn = exts.get("alpn", [])
        supported_ver = exts.get("supported_version")
        tls_version = _ver_str(supported_ver or client_ver)
        esni = "esni" in exts["types"]
        ech = ("ech" in exts["types"]) or exts.get("ech", False)

        # JA3 (OpenGhost/JA3 标准拼接)
        ja3 = ""
        try:
            curves = exts.get("curves", [])
            formats = exts.get("ecpf", [])
            ja3_str = ",".join([
                str(client_ver),
                "-".join(str(c) for c in ciphers),
                "-".join(str(t) for t in exts["types"]),
                "-".join(str(c) for c in curves),
                "-".join(str(f) for f in formats),
            ])
            ja3 = hashlib.md5(ja3_str.encode()).hexdigest()
        except Exception:
            pass
        return {
            "tls_version": tls_version,
            "sni": sni,
            "alpn": alpn,
            "ja3": ja3,
            "esni": esni,
            "ech": ech,
            "ciphers_count": len(ciphers),
        }
    except Exception:
        return None


def _ver_str(v):
    return {0x0301: "TLS1.0", 0x0302: "TLS1.1", 0x0303: "TLS1.2",
            0x0304: "TLS1.3", 0x0300: "SSL3.0"}.get(v, hex(v))


def _parse_extensions(buf: bytes):
    out = {"types": [], "alpn": [], "curves": [], "ecpf": [], "sni": None,
           "supported_version": None, "ech": False}
    p = 0
    while p + 4 <= len(buf):
        etype = (buf[p] << 8) | buf[p + 1]
        elen = (buf[p + 2] << 8) | buf[p + 3]
        edata = buf[p + 4: p + 4 + elen]
        p += 4 + elen
        out["types"].append(etype)
        if etype == 0x0000 and edata:  # SNI
            try:
                # server_name_list: len(2) type(1) len(2) name
                if edata[2] == 0:
                    nlen = (edata[3] << 8) | edata[4]
                    out["sni"] = edata[5:5 + nlen].decode("ascii", "replace")
            except Exception:
                pass
        elif etype == 0x0010:  # ALPN (先跳过 2 字节 ALPNProtocolListLength)
            try:
                q = 2
                while q + 2 <= len(edata):
                    l = (edata[q] << 8) | edata[q + 1]
                    out["alpn"].append(edata[q + 2:q + 2 + l].decode("ascii", "replace"))
                    q += 2 + l
            except Exception:
                pass
        elif etype == 0x000A and len(edata) >= 2:  # supported_groups
            n = (edata[0] << 8) | edata[1]
            for i in range(min(n // 2, 64)):
                if 2 + 2 * i + 1 < len(edata):
                    out["curves"].append((edata[2 + 2 * i] << 8) | edata[3 + 2 * i])
        elif etype == 0x000D and len(edata) >= 2:  # ec_point_formats
            n = edata[0]
            for i in range(min(n, 16)):
                if 1 + i < len(edata):
                    out["ecpf"].append(edata[1 + i])
        elif etype == 0x002B and len(edata) >= 2:  # supported_versions
            out["supported_version"] = (edata[0] << 8) | edata[1]
        elif etype == 0xFFCE:  # encrypted_server_name (ESNI draft18)
            out["types"].append("esni")
        elif etype in (0xFE0D, 0xFE03, 0xFE0C, 0xFE0E):  # ECH 各草案版本
            out["types"].append("ech")
            out["ech"] = True
    return out
