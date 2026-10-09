"""Tkinter 原生 GUI (不做美化, 功能优先).

布局 (自上而下):
  ┌ 顶部:  热点配置区  (SSID/密码/频段/最大连接数 | 应用/启动/停止 | 状态)
  ├ 中部:  客户端表格  (MAC/IP/上线时间/速率/总流量/配额/标记) + 右键管控菜单
  ├ 下部:  设备详情    (Notebook: 流量构成 / 实时会话 / DNS记录 / 告警与日志)
  ├ 图表:  Canvas 简易柱状图 (各设备实时下行速率)
  └ 底部:  状态栏      (抓包状态/包速率/热点状态/数据库体积/法律提示)

所有后台数据经 queue + after() 进入 UI 线程, 避免跨线程操作 Tkinter。
"""
import queue
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, simpledialog, ttk

from . import firewall, hotspot
from .legal import SHORT_NOTICE
from .tls_meta import CATEGORY_LIST

# 业务类型的中文显示名与图表配色
CAT_ZH = {"Video": "视频", "Text": "文本", "Download": "下载", "Game": "游戏",
          "Web": "网页", "DNS": "域名解析", "VoIP": "通话", "P2P": "P2P",
          "Unknown": "其他"}
CAT_COLOR = {"Video": "#e74c3c", "Text": "#3498db", "Download": "#9b59b6",
             "Game": "#e67e22", "Web": "#2ecc71", "DNS": "#95a5a6",
             "VoIP": "#f1c40f", "P2P": "#34495e", "Unknown": "#bdc3c7"}

# 行为分析: 域名特征 -> 应用/行为推断 (仅匹配已记录的明文DNS/SNI域名, 认不出=其他)
APP_SIGS = [
    ("广告SDK", ("pangolin", "pangle", "gdt.qq", "gdtimg", "mobads", "ksadx",
                "doubleclick", "googlesyndication", "applovin", "mintegral",
                "mobvista", "umeng", "unityads")),
    ("抖音", ("douyin", "amemv", "snssdk", "bytecdn", "zjcdn")),
    ("淘宝/天猫", ("taobao", "tmall", "alicdn", "taobaocdn")),
    ("拓竹Studio", ("bambu", "makerworld")),
    ("喜马拉雅", ("ximalaya", "xmcdn")),
    ("飞书", ("feishu", "larkoffice", "larksuite")),
    ("钉钉", ("dingtalk",)),
    ("微信", ("weixin", "wechat", "wx.qq.", "wxapp", "qlogo")),
    ("腾讯视频", ("qqvideo", "v.qq.com", "video.qq", "smtcdns")),
    ("腾讯会议", ("tencentmeet", "meeting.tencent", "woocdn")),
    ("腾讯SDK(后台)", ("bugly.qq", "gdt.qq", "sdk.e.qq", "tdid.m.qq")),
    ("QQ系(后台SDK)", (".qq.com", "gtimg", "qpic.cn")),
    ("网易云音乐", ("music.163", "netease", "126.net")),
    ("百度网盘", ("pan.baidu", "bcebos", "baidupan")),
    ("百度地图SDK", ("map.baidu",)),
    ("百度系(后台SDK)", ("baidu", "bdstatic", "bdimg")),
    ("阿里云盘", ("alipan", "aliyundrive")),
    ("京东", ("jd.com", "360buyimg", "jcloud")),
    ("拼多多", ("pinduoduo", "yangkeduo")),
    ("小红书", ("xiaohongshu", "xhscdn", "xhslink")),
    ("微博", ("weibo", "weibocdn", "sinaimg", "sinajs")),
    ("知乎", ("zhihu", "zhimg")),
    ("B站", ("bilibili", "hdslb", "b23.tv")),
    ("爱奇艺", ("iqiyi", "qy.net")),
    ("美团", ("meituan", "dianping")),
    ("饿了么", ("ele.me", "elemecdn", "eleme")),
    ("携程", ("ctrip", "qunar", "trip.com")),
    ("游戏平台", ("steam", "epicgames", "xbox", "psn", "playstation",
                  "mihoyo", "taptap")),
    ("GitHub", ("github", "githubusercontent", "githubassets")),
    ("YouTube", ("youtube", "googlevideo", "ytimg")),
    ("谷歌服务(后台)", ("google", "gstatic")),
    ("苹果", ("apple.com", "icloud", "mzstatic")),
    ("微软", ("microsoft", "windowsupdate", "office.com", "live.com",
              "msn.com", "msftconnect")),
]


def _fmt_bps(v):
    if v >= 1048576:
        return f"{v/1048576:.1f} MB/s"
    if v >= 1024:
        return f"{v/1024:.1f} KB/s"
    return f"{v:.0f} B/s"


def _fmt_bytes(v):
    if v >= 1073741824:
        return f"{v/1073741824:.2f} GB"
    if v >= 1048576:
        return f"{v/1048576:.1f} MB"
    if v >= 1024:
        return f"{v/1024:.1f} KB"
    return f"{v} B"


def _fmt_time(ts):
    if not ts:
        return "-"
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def _fmt_dt(ts):
    if not ts:
        return "-"
    return datetime.fromtimestamp(ts).strftime("%m-%d %H:%M:%S")


class App:
    def __init__(self, config, storage, sniffer, monitor, alerts, control, dpi):
        self.config = config
        self.storage = storage
        self.sniffer = sniffer
        self.monitor = monitor
        self.alerts = alerts
        self.control = control
        self.dpi = dpi
        self.ui_queue = queue.Queue()
        self._selected_mac = None
        self._chart_data = {}

        self.root = tk.Tk()
        self.root.title("Self-AP-Monitor - Windows 移动热点元数据观测 (仅限本人设备测试)")
        self.root.geometry("1150x780")
        self.root.minsize(980, 620)

        self._build_menu()
        self._build_top()
        self._build_client_table()
        self._build_detail()
        self._build_chart()
        self._build_statusbar()

        self.root.after(50, self._poll_ui_queue)
        self.root.after(self.config.get("ui_refresh_ms"), self._refresh_tables)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ================= 菜单 =================
    def _build_menu(self):
        m = tk.Menu(self.root)
        fm = tk.Menu(m, tearoff=0)
        fm.add_command(label="导出 CSV 报表...", command=self._export_csv)
        fm.add_separator()
        fm.add_command(label="清理全部 SELFAPMON 系统规则", command=self._cleanup_rules)
        fm.add_separator()
        fm.add_command(label="退出", command=self._on_close)
        m.add_cascade(label="文件", menu=fm)

        cm = tk.Menu(m, tearoff=0)
        self._var_domain_block = tk.BooleanVar(value=self.config.get("domain_block_enabled"))
        self._var_cat_block = tk.BooleanVar(value=self.config.get("category_block_enabled"))
        cm.add_checkbutton(label="启用域名黑名单", variable=self._var_domain_block,
                           command=self._toggle_domain_block)
        cm.add_command(label="域名黑名单管理...", command=self._edit_domain_blacklist)
        self._var_short_video = tk.BooleanVar(value=self.config.get("block_short_video"))
        cm.add_checkbutton(label="屏蔽短视频App (抖音/快手/微视, 内置域名)", variable=self._var_short_video,
                           command=self._toggle_short_video)
        self._var_ad_purify = tk.BooleanVar(value=self.config.get("ad_purify_enabled"))
        cm.add_checkbutton(label="网络净化 (拦截穿山甲/优量汇等广告SDK)", variable=self._var_ad_purify,
                           command=self._toggle_ad_purify)
        self._var_dnsf = tk.BooleanVar(value=self.config.get("dns_filter_enabled"))
        cm.add_checkbutton(label="DNS过滤 (域名拦截/设备断网的执行层, 需热点开启)",
                           variable=self._var_dnsf, command=self._toggle_dns_filter)
        self._var_conn_kill = tk.BooleanVar(value=self.config.get("conn_kill_enabled"))
        cm.add_checkbutton(label="连接阻断-主动RST/VN (断网/踢除全杀+短视频拦截, 仅自家热点)",
                           variable=self._var_conn_kill, command=self._toggle_conn_kill)
        self._var_arp_kill = tk.BooleanVar(value=self.config.get("arp_kill_enabled"))
        cm.add_checkbutton(label="ARP断流 (断网设备回程黑洞, 杀已建立QUIC连接, 仅自家热点)",
                           variable=self._var_arp_kill, command=self._toggle_arp_kill)
        self._var_warn_page = tk.BooleanVar(value=self.config.get("warn_page_enabled"))
        cm.add_checkbutton(label="断网警告页 (被断网设备浏览器自动弹出提示页)",
                           variable=self._var_warn_page, command=self._toggle_warn_page)
        cm.add_checkbutton(label="启用流量类型阻断", variable=self._var_cat_block,
                           command=self._toggle_cat_block)
        cm.add_command(label="类型阻断规则管理...", command=self._edit_category_block)
        m.add_cascade(label="管控", menu=cm)

        tm = tk.Menu(m, tearoff=0)
        tm.add_command(label="设备白名单管理...", command=self._edit_whitelist)
        tm.add_command(label="设备黑名单管理...", command=self._edit_mac_blacklist)
        tm.add_command(label="打开数据目录", command=self._open_datadir)
        m.add_cascade(label="工具", menu=tm)

        hm = tk.Menu(m, tearoff=0)
        hm.add_command(label="法律与安全声明", command=self._show_legal)
        hm.add_command(label="关于", command=self._show_about)
        m.add_cascade(label="帮助", menu=hm)
        self.root.config(menu=m)

    # ================= 顶部: 热点配置 =================
    def _build_top(self):
        fr = ttk.LabelFrame(self.root, text="热点配置 (Windows 移动热点)")
        fr.pack(fill="x", padx=6, pady=4)

        ttk.Label(fr, text="SSID:").grid(row=0, column=0, sticky="e", padx=4, pady=3)
        self.e_ssid = ttk.Entry(fr, width=22)
        self.e_ssid.insert(0, self.config.get("hotspot_ssid"))
        self.e_ssid.grid(row=0, column=1, padx=4)

        ttk.Label(fr, text="WPA2密码:").grid(row=0, column=2, sticky="e", padx=4)
        self.e_pass = ttk.Entry(fr, width=22, show="*")
        self.e_pass.insert(0, self.config.get("hotspot_password"))
        self.e_pass.grid(row=0, column=3, padx=4)

        ttk.Label(fr, text="频段:").grid(row=0, column=4, sticky="e", padx=4)
        self.cb_band = ttk.Combobox(fr, width=10, state="readonly",
                                    values=["Auto", "WiFi24GHz", "WiFi50GHz"])
        self.cb_band.set(self.config.get("hotspot_band"))
        self.cb_band.grid(row=0, column=5, padx=4)

        ttk.Label(fr, text="最大连接:").grid(row=0, column=6, sticky="e", padx=4)
        self.sp_max = ttk.Spinbox(fr, from_=1, to=32, width=4)
        self.sp_max.set(self.config.get("max_clients"))
        self.sp_max.grid(row=0, column=7, padx=4)

        self.btn_apply = ttk.Button(fr, text="应用配置", command=self._apply_config)
        self.btn_apply.grid(row=0, column=8, padx=6)
        self.btn_start = ttk.Button(fr, text="启动热点", command=self._start_hotspot)
        self.btn_start.grid(row=0, column=9, padx=3)
        self.btn_stop = ttk.Button(fr, text="停止热点", command=self._stop_hotspot)
        self.btn_stop.grid(row=0, column=10, padx=3)
        self.btn_rescan = ttk.Button(fr, text="刷新", command=self._manual_refresh)
        self.btn_rescan.grid(row=0, column=11, padx=3)
        self.btn_unblock_all = ttk.Button(fr, text="一键恢复全部", command=self._unblock_all)
        self.btn_unblock_all.grid(row=0, column=12, padx=3)

        self.lbl_hs_status = ttk.Label(fr, text="热点状态: 未知 | SSID: - | 客户端: -/-")
        self.lbl_hs_status.grid(row=1, column=0, columnspan=13, sticky="w", padx=6, pady=(0, 3))

        # DPI 后端显示
        self.lbl_dpi = ttk.Label(fr, text=f"识别引擎: {self.dpi.info()} | {SHORT_NOTICE}")
        self.lbl_dpi.grid(row=2, column=0, columnspan=13, sticky="w", padx=6)

    # ================= 中部: 客户端表格 =================
    def _build_client_table(self):
        fr = ttk.LabelFrame(self.root, text="接入设备 (右键: 管控菜单)")
        fr.pack(fill="both", expand=True, padx=6, pady=4)

        cols = ("mac", "ip", "state", "since", "down", "up", "total", "quota", "mark", "alias")
        self.tv = ttk.Treeview(fr, columns=cols, show="headings", height=8)
        heads = {"mac": ("MAC地址", 150), "ip": ("内网IP", 110),
                 "state": ("状态", 55), "since": ("首次上线", 110),
                 "down": ("下行速率", 85), "up": ("上行速率", 85),
                 "total": ("总流量", 90), "quota": ("配额", 90), "mark": ("标记", 130),
                 "alias": ("设备别名", 100)}
        for c in cols:
            t, w = heads[c]
            self.tv.heading(c, text=t)
            self.tv.column(c, width=w, anchor="w" if c in ("mac", "mark") else "center")
        vs = ttk.Scrollbar(fr, orient="vertical", command=self.tv.yview)
        self.tv.configure(yscrollcommand=vs.set)
        self.tv.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        self.tv.bind("<<TreeviewSelect>>", self._on_select_client)

        self.menu_client = tk.Menu(self.root, tearoff=0)
        self.menu_client.add_command(label="切断外网", command=lambda: self._act("block"))
        self.menu_client.add_command(label="恢复外网", command=lambda: self._act("unblock"))
        self.menu_client.add_command(label="一键恢复全部设备外网", command=self._unblock_all)
        self.menu_client.add_command(label="踢除设备 (DNS+连接层全杀)", command=lambda: self._act("kick"))
        self.menu_client.add_command(label="彻底断网 (重启热点, 杀死全部既有连接)",
                                     command=lambda: self._act("hardkill"))
        self.menu_client.add_command(label="弹出指定页面 (网页认证跳转)...",
                                     command=self._set_portal)
        self.menu_client.add_command(label="取消弹出页面",
                                     command=lambda: self._act("unportal"))
        self.menu_client.add_separator()
        self.menu_client.add_command(label="QoS限速 (MB/s)...", command=lambda: self._act("limit"))
        self.menu_client.add_command(label="取消限速", command=lambda: self._act("unlimit"))
        self.menu_client.add_command(label="设置流量配额 (MB)...", command=lambda: self._act("quota"))
        self.menu_client.add_command(label="清除配额", command=lambda: self._act("unquota"))
        self.menu_client.add_separator()
        self.menu_client.add_command(label="加入白名单", command=lambda: self._act("whitelist"))
        self.menu_client.add_command(label="移出白名单", command=lambda: self._act("unwhitelist"))
        self.menu_client.add_command(label="加入黑名单(自动断网)", command=lambda: self._act("blacklist"))
        self.menu_client.add_command(label="移出黑名单", command=lambda: self._act("unblacklist"))
        self.menu_client.add_separator()
        self.menu_client.add_command(label="清空该设备流量统计", command=lambda: self._act("clear"))
        self.menu_client.add_command(label="设置设备别名...", command=self._set_alias)
        self.tv.bind("<Button-3>", self._popup_client_menu)

    # ================= 下部: 设备详情 =================
    def _build_detail(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", padx=6, pady=4)

        # Tab1 概览
        f1 = ttk.Frame(nb)
        nb.add(f1, text="设备详情")
        self.lbl_detail = tk.Label(f1, text="点击上方表格选择设备", anchor="w", justify="left")
        self.lbl_detail.pack(fill="x", padx=6, pady=4)

        # Tab2 实时会话
        f2 = ttk.Frame(nb)
        nb.add(f2, text="实时会话")
        cols = ("raddr", "proto", "category", "up", "down", "sni", "tls", "ech", "ja3")
        self.tv_flows = ttk.Treeview(f2, columns=cols, show="headings", height=7)
        fh = {"raddr": ("对端地址", 150), "proto": ("协议", 55), "category": ("识别类别", 80),
              "up": ("上行", 80), "down": ("下行", 80), "sni": ("SNI", 200),
              "tls": ("TLS", 65), "ech": ("ECH", 45), "ja3": ("JA3", 240)}
        for c in cols:
            t, w = fh[c]
            self.tv_flows.heading(c, text=t)
            self.tv_flows.column(c, width=w, anchor="center" if c in ("proto", "category", "tls", "ech") else "w")
        vs2 = ttk.Scrollbar(f2, orient="vertical", command=self.tv_flows.yview)
        self.tv_flows.configure(yscrollcommand=vs2.set)
        self.tv_flows.pack(side="left", fill="both", expand=True)
        vs2.pack(side="right", fill="y")

        # Tab3 DNS 记录
        f3 = ttk.Frame(nb)
        nb.add(f3, text="DNS记录(库)")
        # 加密DNS解决方案开关条
        bar3 = ttk.Frame(f3)
        bar3.pack(fill="x", pady=(4, 0))
        self._var_force_plain = tk.BooleanVar(value=self.config.get("force_plain_dns"))
        self._var_sni_fb = tk.BooleanVar(value=self.config.get("sni_fallback_enabled"))
        ttk.Label(bar3, text="加密DNS解决方案:").pack(side="left", padx=(6, 2))
        ttk.Checkbutton(bar3, text="强制降级 (可能断网)", variable=self._var_force_plain,
                        command=self._toggle_force_plain).pack(side="left", padx=4)
        ttk.Checkbutton(bar3, text="提取SNI (可能失败)", variable=self._var_sni_fb,
                        command=self._toggle_sni_fallback).pack(side="left", padx=4)

        cols3 = ("time", "mac", "qname", "qtype", "enc", "ech")
        self.tv_dns = ttk.Treeview(f3, columns=cols3, show="headings", height=7)
        fh3 = {"time": ("时间", 110), "mac": ("MAC", 140), "qname": ("域名", 330),
               "qtype": ("类型", 120), "enc": ("加密", 40), "ech": ("ECH", 40)}
        for c in cols3:
            t, w = fh3[c]
            self.tv_dns.heading(c, text=t)
            self.tv_dns.column(c, width=w, anchor="center" if c in ("qtype", "enc", "ech") else "w")
        vs3 = ttk.Scrollbar(f3, orient="vertical", command=self.tv_dns.yview)
        self.tv_dns.configure(yscrollcommand=vs3.set)
        self.tv_dns.pack(side="left", fill="both", expand=True)
        vs3.pack(side="right", fill="y")

        # Tab4 告警与日志
        f4 = ttk.Frame(nb)
        nb.add(f4, text="告警/日志")
        self.txt_log = tk.Text(f4, height=8, wrap="none", state="disabled")
        self.txt_log.pack(fill="both", expand=True)

    # ================= 图表 & 状态栏 =================
    def _build_chart(self):
        fr = ttk.LabelFrame(self.root, text="实时下行速率 (各设备, 简易柱状图)")
        fr.pack(fill="x", padx=6, pady=4)
        self.canvas = tk.Canvas(fr, height=110, bg="white")
        self.canvas.pack(fill="x")

    def _build_statusbar(self):
        sb = ttk.Frame(self.root)
        sb.pack(fill="x", side="bottom")
        self.lbl_status = ttk.Label(sb, text="就绪")
        self.lbl_status.pack(side="left", padx=6)
        self.lbl_db = ttk.Label(sb, text="DB: -")
        self.lbl_db.pack(side="right", padx=6)
        self.lbl_notice = ttk.Label(sb, text=SHORT_NOTICE, foreground="#a00")
        self.lbl_notice.pack(side="right", padx=12)

    # ================= UI 队列 / 告警 =================
    def _poll_ui_queue(self):
        try:
            while True:
                item = self.ui_queue.get_nowait()
                if item.get("type") == "toast":
                    self._log_line(f"[{item.get('tag','')}] {item.get('msg','')}")
                elif item.get("type") == "alert":
                    kind, mac, msg, popup = item["kind"], item["mac"], item["msg"], item.get("popup", True)
                    self._log_line(f"[告警:{kind}] {msg}")
                    if popup:
                        messagebox.showwarning(f"Self-AP-Monitor 告警 - {kind}", msg, parent=self.root)
        except queue.Empty:
            pass
        self.root.after(200, self._poll_ui_queue)

    def _toast(self, tag, msg):
        self.ui_queue.put({"type": "toast", "tag": tag, "msg": msg})

    def _log_line(self, line):
        self.txt_log.configure(state="normal")
        self.txt_log.insert("1.0", f"{datetime.now().strftime('%H:%M:%S')}  {line}\n")
        # 限制行数
        if int(self.txt_log.index("end-1c").split(".")[0]) > 400:
            self.txt_log.delete("400.0", "end")
        self.txt_log.configure(state="disabled")

    # ================= 热点操作 =================
    def _apply_config(self):
        ssid = self.e_ssid.get().strip()
        pwd = self.e_pass.get()
        band = self.cb_band.get()
        try:
            mx = int(self.sp_max.get())
        except ValueError:
            mx = 8
        self.config.set("hotspot_ssid", ssid)
        self.config.set("hotspot_password", pwd)
        self.config.set("hotspot_band", band)
        self.config.set("max_clients", mx)
        self.root.after(0, lambda: self._ps_task(
            lambda: hotspot.configure(ssid, pwd, band, mx),
            "应用热点配置", done=self._manual_refresh))

    def _start_hotspot(self):
        self.root.after(0, lambda: self._ps_task(hotspot.start, "启动热点", done=self._after_hs_change))

    def _stop_hotspot(self):
        self.root.after(0, lambda: self._ps_task(hotspot.stop, "停止热点", done=self._after_hs_change))

    def _unblock_all(self):
        if not messagebox.askyesno(
                "一键恢复",
                "清除本程序下发的全部阻断规则?\n(包含: 踢除/切断外网/域名阻断/类型阻断, QoS限速不受影响)"):
            return
        threading.Thread(target=self.control.unblock_all, daemon=True).start()

    def _set_alias(self):
        mac = self._selected_mac
        if not mac:
            messagebox.showinfo("提示", "请先在上方表格中选择设备", parent=self.root)
            return
        cur = self.config.get_alias(mac)
        name = simpledialog.askstring("设备别名", f"给设备 {mac} 起个名字 (留空清除):",
                                      initialvalue=cur, parent=self.root)
        if name is None:
            return
        self.config.set_alias(mac, name)
        self._toast("别名", f"{mac}: {name.strip() or '(已清除)'}")

    def _set_portal(self):
        mac = self._selected_mac
        if not mac:
            messagebox.showinfo("提示", "请先在上方表格中选择设备", parent=self.root)
            return
        cur = self.control.portal_macs.get(mac, "")
        url = simpledialog.askstring(
            "弹出指定页面",
            f"设备 {mac} 重连热点时, 以\"网页认证\"弹出网页\n"
            f"并 301 重定向到下面输入的网址 (HTTP/HTTPS):\n"
            f"(留空确定 = 取消该设备的弹出页面)",
            initialvalue=cur, parent=self.root)
        if url is None:
            return
        url = url.strip()
        if url and not url.lower().startswith(("http://", "https://")):
            messagebox.showerror("错误", "网址需以 http:// 或 https:// 开头",
                                 parent=self.root)
            return
        threading.Thread(target=self.control.set_portal, args=(mac, url),
                         daemon=True).start()

    def _after_hs_change(self):
        # 热点开关切换后: 等虚拟网卡出现 -> 自动(重)启抓包
        time.sleep(2)
        self._manual_refresh()
        if self.config.get("sniff_enabled"):
            ok, msg = self.sniffer.start()
            self._toast("抓包", msg)

    def _ps_task(self, fn, tag, done=None):
        def work():
            try:
                r = fn()
                self.ui_queue.put({"type": "toast", "tag": tag,
                                   "msg": r.msg if hasattr(r, "msg") else str(r)})
            except Exception as e:
                self.ui_queue.put({"type": "toast", "tag": tag, "msg": f"错误: {e}"})
            if done:
                done()
        threading.Thread(target=work, daemon=True).start()

    def _manual_refresh(self):
        def work():
            st = self.monitor.refresh_hotspot_status()
            self.ui_queue.put({"type": "hotspot_status", "data": st})
        threading.Thread(target=work, daemon=True).start()

    # ================= 客户端表格刷新 =================
    def _refresh_tables(self):
        try:
            rates = self.sniffer.get_rates()
            clients = self.monitor.get_clients()
            # 整表重建会清空选中/滚动, 先保存后恢复
            prev_sel = list(self.tv.selection())
            prev_yview = self.tv.yview()
            for iid in self.tv.get_children():
                self.tv.delete(iid)
            for mac, c in sorted(clients.items(), key=lambda kv: (not kv[1]["online"], kv[0])):
                r = rates.get(mac, {"down_bps": 0, "up_bps": 0, "total_bytes": 0})
                marks = []
                if self.config.is_whitelisted(mac):
                    marks.append("白名单")
                if self.config.is_blacklisted(mac):
                    marks.append("黑名单")
                if self.control.is_blocked(mac):
                    marks.append("已断网")
                if not self.config.is_whitelisted(mac) and not self.config.is_blacklisted(mac):
                    marks.append("陌生")
                q = self.config.get_quota_mb(mac)
                quota_txt = f"{r['total_bytes']/1048576:.0f}/{q:.0f}MB" if q else "-"
                self.tv.insert("", "end", iid=mac, values=(
                    mac, c["ip"], "在线" if c["online"] else "离线",
                    _fmt_dt(c["first_seen"]),
                    _fmt_bps(r["down_bps"]), _fmt_bps(r["up_bps"]),
                    _fmt_bytes(r["total_bytes"]), quota_txt,
                    " ".join(marks), self.config.get_alias(mac)))
            still = [m for m in prev_sel if self.tv.exists(m)]
            if still:
                self.tv.selection_set(still)
                self.tv.focus(still[0])
            if prev_yview and prev_yview[0] > 0:
                self.tv.yview_moveto(prev_yview[0])
            # 热点状态
            hs = getattr(self.monitor, "hotspot_status", {})
            if hs:
                self.lbl_hs_status.config(text=(
                    f"热点状态: {hs.get('state_name','-')} | SSID: {hs.get('ssid','-')} | "
                    f"客户端: {hs.get('clients','-')}/{hs.get('maxClients','-')} | "
                    f"频段: {hs.get('band','-')}"))
            # 会话表
            for iid in self.tv_flows.get_children():
                self.tv_flows.delete(iid)
            flows = self.sniffer.get_active_flows(self._selected_mac, limit=100)
            for f in flows:
                self.tv_flows.insert("", "end", values=(
                    f"{f['raddr']}:{f['dport']}", "TCP" if f["proto"] == 6 else "UDP",
                    f["category"], _fmt_bytes(f["bytes_up"]), _fmt_bytes(f["bytes_down"]),
                    f["sni"], f["tls_version"], "是" if f["ech"] else "", f["ja3"]))
            # DNS 表 (最近库记录)
            dns_rows = self.storage.query("dns_log", limit=80)
            for iid in self.tv_dns.get_children():
                self.tv_dns.delete(iid)
            for d in dns_rows:
                self.tv_dns.insert("", "end", values=(
                    _fmt_dt(d["ts"]), d["mac"], d["qname"], d["qtype"],
                    "是" if d["encrypted"] else "", "是" if d["ech"] else ""))
            # 图表
            self._draw_chart(rates)
            # 告警采样
            for mac, r in rates.items():
                if not self.monitor.get_client(mac) or self.monitor.get_client(mac).online:
                    self.alerts.rate_sample(mac, r["down_bps"])
            self.control.check_quotas(rates)
            self.control.check_ad_suspects()
            # 状态栏
            st = self.sniffer.stats()
            self.lbl_status.config(text=(
                f"抓包: {'运行中' if st['running'] else '停止' + ('(' + st['err'] + ')' if st['err'] else '')} | "
                f"{st['pps']:.0f} pkt/s | 活动流: {st['flows']} | "
                f"识别引擎: {self.dpi.info()}"))
            self.lbl_db.config(text=f"DB: {self.storage.db_size_mb():.1f} MB")
            # 选中设备详情
            self._update_detail()
        except Exception as e:
            self._log_line(f"UI刷新异常: {e}")
        self.root.after(self.config.get("ui_refresh_ms"), self._refresh_tables)

    # ================= 图表 =================
    def _dev_label(self, mac):
        """柱子标签: 别名 > 内网IP末段 > MAC尾号."""
        a = self.config.get_alias(mac)
        if a:
            return a
        c = self.monitor.get_client(mac)
        if c and getattr(c, "ip", ""):
            return c.ip.split(".")[-1]
        return mac.replace(":", "")[-6:]

    def _draw_chart(self, rates):
        cv = self.canvas
        cv.delete("all")
        w = max(cv.winfo_width(), 400)
        h = max(cv.winfo_height(), 80)
        items = [(m, r) for m, r in rates.items()]
        items.sort(key=lambda kv: -kv[1]["down_bps"])
        items = items[:8]
        cv.create_text(10, 6, anchor="w", fill="#555", font=("TkDefaultFont", 8),
                       text="各设备实时下行速率 (最近5秒, 柱越高越快; 标签=IP末段)   "
                            "柱内颜色=流量构成:")
        if not items:
            cv.create_text(w // 2, h // 2, text="暂无流量数据 (设备连上热点产生流量后显示)",
                           fill="#999")
            return
        maxv = max(r["down_bps"] for _, r in items) or 1
        n = len(items)
        bw = min(60, (w - 60) // max(n, 1) - 12)
        base = h - 24          # 柱子底部基线
        x = 20
        legend = {}            # 汇总各类型字节量, 用于图例
        for mac, r in items:
            v = r["down_bps"]
            bh = max(2, int((v / maxv) * (h - 48)))
            cats = r.get("categories") or {}
            csum = sum(cats.values())
            y = base
            if csum > 0:
                # 按构成占比把柱子分段着色 (占比大的画在下面)
                for k, cb in sorted(cats.items(), key=lambda kv: -kv[1]):
                    seg_h = int(bh * cb / csum)
                    seg_h = min(seg_h, y - (base - bh))
                    if seg_h < 1 and y - seg_h >= base - bh:
                        seg_h = 1
                    if seg_h < 1:
                        break
                    cv.create_rectangle(x, y - seg_h, x + bw, y,
                                        fill=CAT_COLOR.get(k, "#4a7"), outline="")
                    y -= seg_h
                    legend[k] = legend.get(k, 0) + cb
            else:
                cv.create_rectangle(x, base - bh, x + bw, base, fill="#4a7", outline="")
            cv.create_text(x + bw // 2, base + 9, font=("TkDefaultFont", 7),
                           text=self._dev_label(mac))
            cv.create_text(x + bw // 2, base - bh - 8, font=("TkDefaultFont", 7),
                           text=_fmt_bps(v))
            x += bw + 12
        # 右上角图例: 出现过的类型, 取字节量最大的4个
        lx = w - 10
        for k, _cb in sorted(legend.items(), key=lambda kv: -kv[1])[:4]:
            tid = cv.create_text(lx, 22, anchor="e", fill="#555",
                                 font=("TkDefaultFont", 8), text=CAT_ZH.get(k, k))
            bb = cv.bbox(tid)
            if bb:
                cv.create_rectangle(bb[0] - 14, (bb[1] + bb[3]) // 2 - 4,
                                    bb[0] - 4, (bb[1] + bb[3]) // 2 + 4,
                                    fill=CAT_COLOR.get(k, "#4a7"), outline="")
                lx = bb[0] - 22

    # ================= 设备选择 / 详情 =================
    def _on_select_client(self, _e=None):
        sel = self.tv.selection()
        self._selected_mac = sel[0] if sel else None
        self._update_detail()

    def _behavior_hint(self, mac, rates):
        """根据近10分钟 DNS 记录 + 流量构成, 推断设备正在干什么."""
        cut = time.time() - 600
        counts = {}
        try:
            rows = self.storage.query("dns_log", limit=300)
        except Exception:
            rows = []
        for d in rows:
            if d.get("mac") != mac or d.get("ts", 0) < cut:
                continue
            q = (d.get("qname") or "").lower()
            if not q:
                continue
            for name, sigs in APP_SIGS:
                if any(s in q for s in sigs):
                    counts[name] = counts.get(name, 0) + 1
                    break
            else:
                counts["其他"] = counts.get("其他", 0) + 1
        top = sorted(counts.items(), key=lambda kv: -kv[1])[:3]
        txt = "、".join(f"{k}({v}次)" for k, v in top) if top else "近10分钟无DNS记录"
        cats = rates.get("categories") or {}
        csum = sum(cats.values())
        if csum:
            k, v = max(cats.items(), key=lambda kv: kv[1])
            txt += f" | 主要流量: {CAT_ZH.get(k, k)} {v / csum:.0%}"
        return txt

    def _update_detail(self):
        mac = self._selected_mac
        if not mac:
            self.lbl_detail.config(text="点击上方表格选择设备")
            return
        c = self.monitor.get_client(mac)
        if not c:
            self.lbl_detail.config(text=f"设备 {mac} (未在热点客户端列表)")
            return
        rates = self.sniffer.get_rates().get(mac, {"down_bps": 0, "up_bps": 0,
                                                   "total_bytes": 0, "up": 0, "down": 0,
                                                   "categories": {}})
        cats = rates.get("categories", {})
        csum = sum(cats.values())
        if csum > 0:
            parts = [f"{CAT_ZH.get(k, k)} {v / csum:.0%} ({_fmt_bytes(v)})"
                     for k, v in sorted(cats.items(), key=lambda kv: -kv[1])[:5]]
            cat_txt = "流量构成 (上线以来各类流量占比): " + "  |  ".join(parts)
        else:
            cat_txt = "流量构成: 暂无可识别流量 (设备看视频/下文件/上网后会自动分类)"
        q = self.config.get_quota_mb(mac)
        alias = self.config.get_alias(mac)
        txt = (f"设备: {alias or '(未设别名)'}   MAC: {mac}   IP: {c.ip}   "
               f"状态: {'在线' if c.online else '离线'}\n"
               f"首次上线: {_fmt_dt(c.first_seen)}   最近活动: {_fmt_dt(c.last_seen)}\n"
               f"下行: {_fmt_bps(rates['down_bps'])}   上行: {_fmt_bps(rates['up_bps'])}   "
               f"总流量: {_fmt_bytes(rates['total_bytes'])}"
               + (f"   配额: {rates['total_bytes']/1048576:.0f}/{q:.0f}MB" if q else "") + "\n"
               f"行为分析(近10分钟): {self._behavior_hint(mac, rates)}\n"
               f"阻断状态: {'已断外网' if self.control.is_blocked(mac) else '正常'}   "
               f"标记: {'白名单' if self.config.is_whitelisted(mac) else '黑名单' if self.config.is_blacklisted(mac) else '陌生'}\n"
               f"{cat_txt}")
        self.lbl_detail.config(text=txt)

    # ================= 管控动作 =================
    def _popup_client_menu(self, ev):
        iid = self.tv.identify_row(ev.y)
        if iid:
            self.tv.selection_set(iid)
            self.menu_client.post(ev.x_root, ev.y_root)

    def _act(self, action):
        mac = self._selected_mac
        if not mac:
            messagebox.showinfo("提示", "请先选择设备", parent=self.root)
            return
        if action == "block":
            self.control.block_internet(mac)
        elif action == "unblock":
            self.control.unblock_internet(mac)
        elif action == "kick":
            if messagebox.askyesno("确认", f"踢除设备 {mac}?\n(DNS解析拦截+连接层RST/VN全杀; "
                                          f"已建立的QUIC连接无法协议内终止, 彻底断开用\"彻底断网\")",
                                   parent=self.root):
                self.control.kick(mac)
        elif action == "hardkill":
            if messagebox.askyesno("确认", f"彻底断网 {mac}?\n\n将重启热点: 全部设备(含其他设备)"
                                          f"会短暂掉线几秒;\n本设备重新连上后立即被"
                                          f"DNS拦截+连接层全杀, 已建立的连接全部死亡。",
                                   parent=self.root):
                threading.Thread(target=self.control.hard_kill, args=(mac,),
                                 daemon=True).start()
        elif action == "unportal":
            if messagebox.askyesno("确认", f"取消设备 {mac} 的弹出页面?\n\n"
                                          f"设备恢复联网, 不再跳转。",
                                   parent=self.root):
                threading.Thread(target=self.control.set_portal,
                                 args=(mac, ""), daemon=True).start()
        elif action == "limit":
            v = simpledialog.askstring("QoS限速", "输入限速值 (MB/s, 例如 1):", parent=self.root)
            if v:
                try:
                    self.control.limit_rate(mac, float(v))
                except ValueError:
                    messagebox.showerror("错误", "无效数值", parent=self.root)
        elif action == "unlimit":
            self.control.remove_rate_limit(mac)
        elif action == "quota":
            v = simpledialog.askstring("流量配额", "输入配额 (MB, 例如 1024):", parent=self.root)
            if v:
                try:
                    self.control.set_quota(mac, float(v))
                except ValueError:
                    messagebox.showerror("错误", "无效数值", parent=self.root)
        elif action == "unquota":
            self.control.clear_quota(mac)
            self._toast("配额", f"{mac}: 配额已清除")
        elif action == "whitelist":
            self.config.add_whitelist(mac)
            self._toast("白名单", f"{mac} 已加入白名单")
        elif action == "unwhitelist":
            self.config.remove_whitelist(mac)
            self._toast("白名单", f"{mac} 已移出白名单")
        elif action == "blacklist":
            if messagebox.askyesno("确认", f"将 {mac} 加入黑名单并立即断网?", parent=self.root):
                self.config.add_blacklist(mac)
                self.control.block_internet(mac)
        elif action == "unblacklist":
            self.config.remove_blacklist(mac)
        elif action == "clear":
            self.sniffer.clear_device(mac)
            self._toast("统计", f"{mac} 流量统计已清零(本地内存)")

    # ================= 全局管控编辑 =================
    def _edit_domain_blacklist(self):
        d = EditListDialog(self.root, "域名黑名单 (支持 *.example.com 通配)",
                           self.config.get("domain_blacklist"))
        if d.result is not None:
            self.config.set("domain_blacklist", [x for x in d.result if x])

    def _toggle_domain_block(self):
        self.config.set("domain_block_enabled", self._var_domain_block.get())

    def _toggle_short_video(self):
        on = bool(self._var_short_video.get())
        self.config.set("block_short_video", on)
        if on:
            # 屏蔽的执行层 = DNS过滤, 未运行则自动拉起 (后台线程, 涉及PS调用)
            def _start():
                ok = self.control._ensure_dnsfilter()
                if self.config.get("conn_kill_enabled"):
                    self.control._ensure_netkill()   # 连接层阻断补HTTPDNS绕过
                self.ui_queue.put({"type": "toast", "tag": "管控", "msg":
                                   ("内置短视频屏蔽已开启: DNS解析返回0.0.0.0"
                                    + (" + 连接层RST/VN阻断" if self.config.get("conn_kill_enabled") else "")
                                    + ("" if ok else "; DNS过滤启动失败, 请确认热点已开启"))})
                self.root.after(0, lambda: self._var_dnsf.set(
                    bool(self.config.get("dns_filter_enabled"))))
            threading.Thread(target=_start, daemon=True).start()
        else:
            self._toast("管控", "内置短视频屏蔽已关闭 (已解析过的IP短期内可能仍可访问)")

    def _toggle_ad_purify(self):
        on = bool(self._var_ad_purify.get())
        self.config.set("ad_purify_enabled", on)
        self._toast("网络净化",
                    ("已开启: 拦截穿山甲/优量汇/百度SSP等广告SDK; "
                     "广告与内容共用的域名按连接数/流量大小推断"
                     if on else "已关闭: 不再拦截广告SDK"))

    def _toggle_dns_filter(self):
        on = bool(self._var_dnsf.get())
        self.config.set("dns_filter_enabled", on)
        threading.Thread(target=self.control.set_dns_filter, args=(on,),
                         daemon=True).start()

    def _toggle_conn_kill(self):
        on = bool(self._var_conn_kill.get())
        self.config.set("conn_kill_enabled", on)
        threading.Thread(target=self.control.set_conn_kill, args=(on,),
                         daemon=True).start()

    def _toggle_arp_kill(self):
        on = bool(self._var_arp_kill.get())
        threading.Thread(target=self.control.set_arp_kill, args=(on,),
                         daemon=True).start()

    def _toggle_warn_page(self):
        on = bool(self._var_warn_page.get())
        self.config.set("warn_page_enabled", on)
        threading.Thread(target=self.control.set_warn_page, args=(on,),
                         daemon=True).start()

    def _toggle_force_plain(self):
        on = bool(self._var_force_plain.get())
        if on and not messagebox.askyesno(
                "强制降级确认",
                "将阻断客户端出站 853 端口 (DoT/DoQ), 并对常见公共 DoH 服务商域名做 SNI 阻断,\n"
                "迫使设备回落到明文 DNS (这样本程序就能看到域名了)。\n\n"
                "注意: 安卓'专用DNS=严格模式'的设备可能完全断网!\n确定开启?"):
            self._var_force_plain.set(False)
            return
        threading.Thread(target=self.control.set_force_plain_dns, args=(on,), daemon=True).start()

    def _toggle_sni_fallback(self):
        on = bool(self._var_sni_fb.get())
        self.config.set("sni_fallback_enabled", on)
        self._toast("提取SNI",
                    ("已开启: DNS加密时改从 TLS 握手 SNI 识别域名 (设备开ECH时会失败)"
                     if on else "已关闭: 不再通过 SNI 识别域名, 只依赖明文DNS"))

    def _edit_category_block(self):
        d = EditListDialog(self.root,
                           "阻断的流量类型 (可选: " + ", ".join(CATEGORY_LIST) + ")",
                           self.config.get("blocked_categories"))
        if d.result is not None:
            self.config.set("blocked_categories", [x for x in d.result if x in CATEGORY_LIST])

    def _toggle_cat_block(self):
        self.config.set("category_block_enabled", self._var_cat_block.get())

    def _edit_whitelist(self):
        d = EditListDialog(self.root, "设备白名单 (MAC, 每行一个)",
                           self.config.get("known_devices"))
        if d.result is not None:
            self.config.set("known_devices", [self.config._norm_mac(x) for x in d.result if x])

    def _edit_mac_blacklist(self):
        d = EditListDialog(self.root, "设备黑名单 (MAC, 每行一个)",
                           self.config.get("blacklist_macs"))
        if d.result is not None:
            self.config.set("blacklist_macs", [self.config._norm_mac(x) for x in d.result if x])

    # ================= 导出 / 工具 =================
    def _export_csv(self):
        table = self._ask_table()
        if not table:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", initialfile=f"{table}_{datetime.now():%Y%m%d_%H%M%S}.csv",
            filetypes=[("CSV 文件", "*.csv")])
        if not path:
            return
        days = simpledialog.askinteger("导出范围", "导出最近多少天的数据?", initialvalue=7, parent=self.root)
        if not days:
            return
        end = time.time()
        start = end - days * 86400
        try:
            n = self.storage.export_csv(table, start, end, path)
            messagebox.showinfo("导出完成", f"已导出 {n} 行到:\n{path}", parent=self.root)
        except Exception as e:
            messagebox.showerror("导出失败", str(e), parent=self.root)

    def _ask_table(self):
        w = tk.Toplevel(self.root)
        w.title("选择导出表")
        w.grab_set()
        var = tk.StringVar(value="dns_log")
        r = [None]
        for i, (val, txt) in enumerate([
                ("dns_log", "DNS 查询记录"), ("flows", "会话/流记录"),
                ("devices", "设备上下线"), ("events", "事件与告警日志")]):
            tk.Radiobutton(w, text=txt, value=val, variable=var).grid(row=i, column=0, sticky="w", padx=20, pady=3)
        def ok():
            r[0] = var.get()
            w.destroy()
        tk.Button(w, text="确定", command=ok).grid(row=4, column=0, pady=8)
        w.wait_window()
        return r[0]

    def _cleanup_rules(self):
        if messagebox.askyesno("确认", "清理本程序创建的全部防火墙/QoS规则?", parent=self.root):
            firewall.cleanup_all_rules()
            self._toast("系统", firewall.cleanup_all_rules())

    def _open_datadir(self):
        import os
        import subprocess
        from . import app_root
        d = os.path.join(app_root(), "data")
        os.makedirs(d, exist_ok=True)
        subprocess.Popen(["explorer", d])

    def _show_legal(self):
        from .legal import LEGAL_NOTICE
        messagebox.showinfo("法律与安全声明", LEGAL_NOTICE, parent=self.root)

    def _show_about(self):
        messagebox.showinfo("关于", "Self-AP-Monitor v1.0\nWindows 移动热点元数据观测与本地管控\n\n"
                            "仅限本人设备测试 | 不解密HTTPS | 无MITM | 无包注入\n"
                            "详见 docs/WINDOWS_LIMITATIONS.md", parent=self.root)

    # ================= 退出 =================
    def _on_close(self):
        if messagebox.askyesno("退出", "退出 Self-AP-Monitor?", parent=self.root):
            # 新版 DNS过滤绑定热点网关:53, 不改主机DNS, 关闭线程即可 (无残留)
            try:
                if self.control.dnsfilter and self.control.dnsfilter.is_alive():
                    self.control.set_dns_filter(False)
            except Exception:
                pass
            try:
                firewall.cleanup_all_rules()
            except Exception:
                pass
            try:
                self.sniffer.stop()
            except Exception:
                pass
            try:
                self.monitor.stop()
            except Exception:
                pass
            try:
                self.storage.close()
            except Exception:
                pass
            self.root.destroy()


class EditListDialog:
    """多行文本编辑器 (通用列表编辑)."""

    def __init__(self, parent, title, items):
        self.result = None
        w = tk.Toplevel(parent)
        w.title(title)
        w.geometry("460x320")
        w.transient(parent)
        w.grab_set()
        tk.Label(w, text=title).pack(anchor="w", padx=8, pady=4)
        txt = tk.Text(w, wrap="none")
        txt.pack(fill="both", expand=True, padx=8)
        txt.insert("1.0", "\n".join(items))
        def ok():
            self.result = [x.strip() for x in txt.get("1.0", "end").splitlines() if x.strip()]
            w.destroy()
        def cancel():
            w.destroy()
        fb = tk.Frame(w)
        fb.pack(fill="x", pady=6)
        tk.Button(fb, text="保存", command=ok).pack(side="right", padx=8)
        tk.Button(fb, text="取消", command=cancel).pack(side="right", padx=8)
        parent.wait_window(w)


def run_gui(config, storage, sniffer, monitor, alerts, control, dpi):
    app = App(config, storage, sniffer, monitor, alerts, control, dpi)
    app.root.mainloop()
