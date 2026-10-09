"""断网警告页: 本机 HTTP 服务 (热点网关IP:80) + DNS 劫持定向.

被断网/踢除设备的 DNS 查询由 DNS 过滤层应答为热点网关 IP (而非
0.0.0.0), 设备访问任何 http:// 站点都会落到本警告页 —— 效果类似
captive portal:
  - Android/iOS 联网检测为明文 HTTP, 系统会自动弹出"需要登录/网络提示"
    窗口, 直接展示本页面
  - 仅覆盖 80 端口明文 HTTP; HTTPS 站点因无证书连接失败 (不做中间人)

合规边界: 仅对自家热点内被管控设备重定向到本机页面, 不伪造任何
第三方业务内容, 不解密任何通信.
"""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE_TMPL = """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>网络访问提示</title><style>
body{margin:0;font-family:-apple-system,"Segoe UI",Roboto,"PingFang SC",
"Microsoft YaHei",sans-serif;background:#f2f3f5;color:#333}
.card{max-width:420px;margin:8vh auto;background:#fff;border-radius:14px;
box-shadow:0 6px 24px rgba(0,0,0,.08);padding:32px 26px;text-align:center}
.icon{width:64px;height:64px;line-height:64px;border-radius:50%;
background:#fff7e6;color:#d48806;font-size:34px;margin:0 auto 16px;
font-weight:700}
h1{font-size:20px;margin:0 0 10px}
p{font-size:14px;line-height:1.8;color:#666;margin:8px 0}
.ip{display:inline-block;margin-top:14px;padding:4px 12px;border-radius:999px;
background:#f2f3f5;color:#999;font-size:12px}
</style></head><body><div class="card">
<div class="icon">!</div>
<h1>网络访问已受限</h1>
<p>您的设备已接入本网络，但当前访问权限被管理员限制。</p>
<p>如需恢复访问，请联系网络管理员。</p>
<span class="ip">设备 IP：{IP}</span>
</div></body></html>"""


def _page(client_ip=""):
    return PAGE_TMPL.replace("{IP}", client_ip).encode("utf-8")


class _Handler(BaseHTTPRequestHandler):
    server_version = "SelfAPMon/1.0"
    protocol_version = "HTTP/1.1"

    def _respond(self, include_body=True):
        try:
            # 弹出指定页面模式: 301 重定向到管理员设置的网址 (captive portal)
            # 注意: handler.server 是 HTTPServer 实例, redirect_url 在外层
            # WarnPageServer 上, 通过 apsrv 引用动态读取
            apsrv = getattr(self.server, "apsrv", None)
            url = str(getattr(apsrv, "redirect_url", "") or "")
            if url:
                body = (f'<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">'
                        f'<meta http-equiv="refresh" content="0;url={url}">'
                        f'</head><body style="margin:0;font-family:sans-serif;text-align:center;'
                        f'padding-top:40vh">正在跳转...</body></html>').encode("utf-8")
                self.send_response(301)
                self.send_header("Location", url)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                if include_body:
                    self.wfile.write(body)
                return
            body = _page(self.client_address[0] if self.client_address else "")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if include_body:
                self.wfile.write(body)
        except Exception:
            pass

    def do_GET(self):
        self._respond(True)

    def do_HEAD(self):
        self._respond(False)

    def do_POST(self):                       # 任何方法都返回页面
        self._respond(True)

    def log_message(self, *args):            # 静默 (不刷控制台)
        pass


class WarnPageServer(threading.Thread):
    """警告页 HTTP 服务. ap_ip_fn() 轮询热点网关 IP, 变更即重绑."""

    def __init__(self, ap_ip_fn=None, port=80):
        super().__init__(daemon=True, name="WarnPage")
        self.ap_ip_fn = ap_ip_fn or (lambda: "")
        self.port = port
        self.redirect_url = ""      # 非空: 所有访问 301 到该网址 (弹出指定页面)
        self._httpd = None
        self._bound_ip = ""
        self._err = ""
        self._stop_ev = threading.Event()

    def bound_ip(self):
        return self._bound_ip

    def last_error(self):
        return self._err

    def run(self):
        while not self._stop_ev.is_set():
            ap_ip = str(self.ap_ip_fn() or "")
            if ap_ip != self._bound_ip:
                self._close()
                if ap_ip:
                    try:
                        self._httpd = ThreadingHTTPServer(
                            (ap_ip, self.port), _Handler)
                        self._httpd.daemon_threads = True
                        self._httpd.apsrv = self    # handler 读 redirect_url 用
                        self._bound_ip = ap_ip
                        self._err = ""
                        threading.Thread(target=self._httpd.serve_forever,
                                         daemon=True, name="WarnPageSrv").start()
                    except OSError as e:
                        self._err = str(e)
                        self._bound_ip = ""
                else:
                    self._bound_ip = ""
            self._stop_ev.wait(5)
        self._close()

    def _close(self):
        if self._httpd:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:
                pass
            self._httpd = None

    def stop(self):
        self._stop_ev.set()
