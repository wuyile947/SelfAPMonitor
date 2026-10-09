"""Self-AP-Monitor 入口.

启动流程:
  1. 启动弹窗: 法律风险提示 (必须点"同意"才能进入, 每次启动都显示)
  2. 管理员权限: 防火墙/QoS/抓包都需要; 提示提权重启或继续受限模式
  3. 组装组件 -> Tkinter 主窗口
"""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from selfapmon import hotspot
from selfapmon.alerts import AlertManager
from selfapmon.config import Config
from selfapmon.control import ControlCenter
from selfapmon.dpi import DpiEngine
from selfapmon.legal import LEGAL_NOTICE
from selfapmon.sniffer import Sniffer
from selfapmon.storage import Storage
from selfapmon.clients import ClientMonitor


def show_legal_dialog() -> bool:
    """启动法律弹窗. 返回是否同意. (纯 Tkinter, 无 Web)"""
    import tkinter as tk
    from tkinter import messagebox

    root = tk.Tk()
    root.title("法律与安全使用声明 - Self-AP-Monitor")
    root.geometry("680x520")
    root.eval("tk::PlaceWindow . center")

    txt = tk.Text(root, wrap="word")
    txt.pack(fill="both", expand=True, padx=10, pady=8)
    txt.insert("1.0", LEGAL_NOTICE)
    txt.configure(state="disabled")

    var = tk.BooleanVar(value=False)

    def agree():
        var.set(True)
        root.destroy()

    def refuse():
        messagebox.showinfo("退出", "未同意声明, 程序将退出。", parent=root)
        root.destroy()

    bf = tk.Frame(root)
    bf.pack(fill="x", pady=6)
    tk.Button(bf, text="我已阅读并同意, 进入程序", width=28, command=agree).pack(side="left", padx=12)
    tk.Button(bf, text="退出", width=12, command=refuse).pack(side="right", padx=12)
    tk.Label(bf, text="本软件仅限本人设备测试 | 不解密内容 | 协议内RST/VN连接终止",
             fg="#a00").pack(side="left", padx=8)
    root.mainloop()
    return var.get()


def ensure_admin_or_continue() -> bool:
    """防火墙/QoS/抓包均需管理员. 返回是否以管理员运行."""
    if hotspot.is_admin():
        return True
    import tkinter as tk
    from tkinter import messagebox
    root = tk.Tk()
    root.withdraw()
    yes = messagebox.askyesno(
        "需要管理员权限",
        "防火墙管控 / QoS限速 / 数据包嗅探均需要管理员权限。\n\n"
        "是  -> 以管理员身份重新启动本程序\n"
        "否  -> 以受限模式继续 (热点开关可用, 管控与抓包将失败)",
        parent=root)
    root.destroy()
    if yes:
        import ctypes
        params = f'"{os.path.abspath(sys.argv[0])}"'
        try:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        except Exception:
            pass
        sys.exit(0)
    return False


def main():
    if os.name != "nt":
        print("本程序仅支持 Windows 10/11")
        sys.exit(1)
    if not show_legal_dialog():
        print("未同意法律声明, 退出")
        sys.exit(0)
    ensure_admin_or_continue()

    config = Config()
    storage = Storage(config)
    dpi = DpiEngine(config)

    control_ref = {"ap_mac": "", "ap_iface": None}  # sniffer <-> control 共享
    sniffer = Sniffer(config, storage, dpi, emit_alert=None, control_ref=control_ref)
    monitor_holder = {}

    def on_alert(kind, mac, msg, popup=True):
        uiq = holder.get("ui_queue")
        if uiq is not None:
            uiq.put({"type": "alert", "kind": kind, "mac": mac, "msg": msg, "popup": popup})

    alerts = AlertManager(config, on_alert, storage)

    def on_event(etype, client):
        """客户端上下线事件 (monitor 线程回调)."""
        if etype == "client_up":
            storage.log_device(client.mac, client.ip, "上线")
            verdict = alerts.client_up(client.mac, client.ip)
            ctl = holder.get("control")
            if ctl:
                if client.mac in ctl.blocked_macs:
                    ctl._sync_blocked_ips()   # 重连换IP -> 立即刷新断网名单
                if verdict == "blacklist":
                    ctl.block_internet(client.mac)
        else:
            storage.log_device(client.mac, client.ip, "下线")

    monitor = ClientMonitor(config, on_event=on_event)
    monitor.set_rate_hook(sniffer.get_rates)
    sniffer.activity_cb = monitor.note_activity   # 抓包实时流量 -> 即时上线
    monitor_holder["monitor"] = monitor

    control = ControlCenter(config, storage, alerts, sniffer, monitor, ui_queue=None)
    control_ref["on_dns_query"] = control.on_dns_query
    control_ref["on_tls_hello"] = control.on_tls_hello
    control_ref["on_flow_classified"] = control.on_flow_classified
    control_ref["on_netkill"] = control.on_netkill

    # 启动自愈: 旧版本可能残留主机DNS指向127.0.0.1 (强杀进程无清理路径) -> 复位
    def heal_host_dns():
        try:
            from selfapmon import dnsfilter
            if dnsfilter.host_dns_stuck():
                dnsfilter.restore_host_dns({})
                storage.log_event("control", "", "", "启动自愈: 残留的127.0.0.1主机DNS已复位")
        except Exception:
            pass
    threading.Thread(target=heal_host_dns, daemon=True).start()

    # 启动时恢复"强制降级"开关 (后台执行, 不阻塞UI)
    if config.get("force_plain_dns"):
        threading.Thread(target=control.set_force_plain_dns, args=(True,), daemon=True).start()
    if config.get("dns_filter_enabled"):
        threading.Thread(target=control.set_dns_filter, args=(True,), daemon=True).start()
    if config.get("conn_kill_enabled"):
        threading.Thread(target=control.set_conn_kill, args=(True,), daemon=True).start()
    if config.get("warn_page_enabled"):
        threading.Thread(target=control.set_warn_page, args=(True,), daemon=True).start()
    if config.get("portal_redirects"):
        threading.Thread(target=control.restore_portals, daemon=True).start()

    # GUI (App 内部会再绑定 control.ui_queue)
    from selfapmon.gui import App

    holder = {}
    app = App(config, storage, sniffer, monitor, alerts, control, dpi)
    holder["ui_queue"] = app.ui_queue
    holder["control"] = control
    holder["root"] = app.root
    control.ui_queue = app.ui_queue
    control._toast = lambda tag, msg: app.ui_queue.put(
        {"type": "toast", "tag": tag, "msg": msg})

    # 热点AP MAC/网卡信息 -> sniffer 方向判断 (周期同步) + 嗅探看门狗
    def sync_ap_info():
        try:
            info = hotspot.find_ap_interface()
            if info:
                control_ref["ap_mac"] = info.get("mac", "")
                control_ref["ap_iface"] = info
        except Exception:
            pass
        try:
            sniffer.watchdog()
        except Exception:
            pass
        app.root.after(30000, sync_ap_info)

    app.root.after(1000, sync_ap_info)

    # 启动自动抓包 (热点可能稍后才开启, 带重试)
    def auto_start_sniff():
        if not config.get("sniff_enabled"):
            return
        ok, msg = False, ""
        for _ in range(15):  # 最多约 90s, 等热点虚拟网卡就绪
            if hotspot.find_ap_interface():
                ok, msg = sniffer.start()
                if ok:
                    break
            time.sleep(6)
        if not msg:
            msg = "热点未开启, 未启动抓包"
        app.ui_queue.put({"type": "toast", "tag": "抓包", "msg": msg})
    threading.Thread(target=auto_start_sniff, daemon=True).start()

    monitor.start()

    try:
        app.root.mainloop()
    finally:
        for c in (monitor, sniffer, storage):
            try:
                c.stop() if hasattr(c, "stop") else c.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
