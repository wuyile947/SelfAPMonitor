"""无线网卡兼容性检测脚本 (Self-AP-Monitor).

用法:
    python check_compatibility.py            # 交互式检测并输出报告
    python check_compatibility.py --write    # 同时保存报告到 data/compat_report.txt

检测项:
  1. 操作系统版本 (需 Win10/11)
  2. Python 版本 (需 3.10+) 与 tkinter 可用性
  3. 管理员权限
  4. 无线网卡存在性与驱动状态
  5. Wi-Fi Direct 虚拟网卡 (移动热点依赖)
  6. 移动热点服务 (icssvc) 与 ICS 服务 (SharedAccess)
  7. WinRT 移动热点 API 可达性 (读取当前热点配置)
  8. Npcap 驱动 (Scapy 抓包依赖)
  9. Scapy 安装与接口枚举
 10. New-NetQosPolicy / New-NetFirewallRule cmdlet 可用性
 11. 可选: libndpi.dll 检测
"""
import ctypes
import os
import subprocess
import sys
import base64

OK, WARN, FAIL = "[OK]  ", "[WARN]", "[FAIL]"
results = []


def add(level, item, detail=""):
    results.append((level, item, detail))
    print(f"{level} {item}" + (f"  -- {detail}" if detail else ""))


def run(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout.decode("utf-8", "replace") + p.stderr.decode("utf-8", "replace")
    except Exception as e:
        return -1, str(e)


def run_ps(script, timeout=40):
    enc = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-EncodedCommand", enc], timeout)


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    print("=" * 70)
    print(" Self-AP-Monitor 无线网卡/系统兼容性检测")
    print(" 仅采集本机系统信息, 不联网, 不修改任何设置")
    print("=" * 70)

    # 1. OS
    win10_plus = sys.getwindowsversion().major >= 10 if hasattr(sys, "getwindowsversion") else False
    add(OK if win10_plus else FAIL,
        f"操作系统: Windows {'10/11' if win10_plus else '版本过低'}",
        f"build {sys.getwindowsversion().build}" if hasattr(sys, "getwindowsversion") else "")

    # 2. Python / tkinter
    py_ok = sys.version_info >= (3, 10)
    add(OK if py_ok else FAIL, f"Python {sys.version.split()[0]}",
        "需要 >= 3.10" if not py_ok else "")
    try:
        import tkinter  # noqa
        add(OK, "tkinter 可用")
    except Exception as e:
        add(FAIL, "tkinter 不可用", str(e))

    # 3. 管理员
    try:
        admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        admin = False
    add(OK if admin else WARN, "管理员权限",
        "已具备" if admin else "当前非管理员; 管控/抓包功能需要, 可右键'以管理员身份运行'")

    # 4. 无线网卡
    rc, out = run(["netsh", "wlan", "show", "drivers"])
    if rc == 0 and "Driver" in out:
        add(OK, "无线网卡驱动 (netsh wlan show drivers)")
        for line in out.splitlines():
            s = line.strip()
            if s.startswith(("描述", "Description", "驱动程序", "Driver version")):
                print("        " + s)
    else:
        add(FAIL, "无线网卡", "未检测到 WLAN 驱动/网卡 (netsh wlan show drivers 失败)")

    # 5. Wi-Fi Direct 虚拟网卡
    rc, out = run_ps(
        "Get-NetAdapter | Where-Object {$_.InterfaceDescription -like '*Microsoft Wi-Fi Direct Virtual*'} | "
        "Select-Object Name,Status,InterfaceDescription | ConvertTo-Json -Compress")
    if rc == 0 and out.strip():
        add(OK, "Wi-Fi Direct 虚拟适配器 (移动热点载体)", out.strip()[:200])
    else:
        add(WARN, "Wi-Fi Direct 虚拟适配器",
            "未发现 (热点未开启时属正常; 开启热点后需出现 'Microsoft Wi-Fi Direct Virtual Adapter')")

    # 6. 服务
    rc, out = run(["sc", "query", "icssvc"])
    svc1 = rc == 0 and "RUNNING" in out
    rc2, out2 = run(["sc", "query", "SharedAccess"])
    svc2 = rc2 == 0 and "RUNNING" in out2
    add(OK if svc1 else WARN, "Windows Mobile Hotspot 服务 (icssvc)",
        "运行中" if svc1 else "未运行 (启动热点时系统会自动拉起)")
    add(OK if svc2 else WARN, "Internet Connection Sharing (SharedAccess)",
        "运行中" if svc2 else "未运行 (启动热点时系统会自动拉起)")

    # 7. WinRT 热点 API
    rc, out = run_ps("""
$ErrorActionPreference='Stop'
try {
  Add-Type -AssemblyName System.Runtime.WindowsRuntime | Out-Null
  $p = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()
  if (-not $p) { Write-Output 'NO_PROFILE'; exit 0 }
  $m = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile($p)
  $c = $m.GetCurrentAccessPointConfiguration()
  Write-Output ('STATE=' + [int]$m.TetheringOperationalState + ' SSID=' + $c.Ssid + ' MAX=' + $m.MaxClientCount)
} catch { Write-Output ('ERR=' + $_.Exception.Message) }
""")
    if rc == 0 and out.startswith("STATE"):
        add(OK, "WinRT 移动热点 API", out.strip())
    elif out.startswith("NO_PROFILE"):
        add(WARN, "WinRT 移动热点 API", "当前无互联网连接配置 (连上网后可用)")
    else:
        add(FAIL, "WinRT 移动热点 API", out.strip() or "调用失败 (需 Windows PowerShell 5.1)")

    # 8. Npcap
    npcap_dir = r"C:\Windows\System32\Npcap"
    rc, out = run(["sc", "query", "npcap"])
    if os.path.isdir(npcap_dir) or (rc == 0 and "RUNNING" in out):
        add(OK, "Npcap 抓包驱动", npcap_dir if os.path.isdir(npcap_dir) else "服务已注册")
    else:
        add(FAIL, "Npcap 抓包驱动", "未安装 -> https://npcap.com/#download (Scapy 抓包必需)")

    # 9. Scapy
    try:
        import scapy  # noqa
        from scapy.all import conf  # noqa
        n_ifaces = len(list(conf.ifaces.values())) if hasattr(conf, "ifaces") else -1
        add(OK, f"Scapy {scapy.__version__} 可用", f"枚举到 {n_ifaces} 个网络接口")
    except Exception as e:
        add(FAIL, "Scapy", f"未安装或加载失败: {e} -> pip install scapy")

    # 10. cmdlet
    rc, out = run_ps("(Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue) -ne $null; "
                     "(Get-Command New-NetQosPolicy -ErrorAction SilentlyContinue) -ne $null")
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    fw_ok = len(lines) >= 1 and lines[0] == "True"
    qos_ok = len(lines) >= 2 and lines[1] == "True"
    add(OK if fw_ok else FAIL, "New-NetFirewallRule cmdlet", "断网/黑名单依赖")
    add(OK if qos_ok else WARN, "New-NetQosPolicy cmdlet",
        "限速依赖 (部分客户端SKU不支持对转发流量限速, 见局限文档)" if qos_ok else "不可用(家用版常见)")

    # 11. nDPI (可选)
    found = None
    for c in ("bin/libndpi.dll", "bin/ndpi.dll"):
        if os.path.exists(c):
            found = c
            break
    if not found:
        for d in os.environ.get("PATH", "").split(os.pathsep):
            if d and os.path.exists(os.path.join(d.strip('" '), "libndpi.dll")):
                found = os.path.join(d, "libndpi.dll")
                break
    add(OK if found else WARN, "nDPI (libndpi.dll)",
        found if found else "未找到 -> 将使用内置启发式识别 (功能完整, 精度略低)")

    # 汇总
    n_fail = sum(1 for lv, _, _ in results if lv == FAIL)
    n_warn = sum(1 for lv, _, _ in results if lv == WARN)
    print("=" * 70)
    print(f"结论: {len(results)-n_fail-n_warn} 项通过, {n_warn} 项警告, {n_fail} 项失败")
    if n_fail == 0:
        print("环境基本满足运行条件。" + ("" if admin else " 请以管理员身份运行主程序。"))
    else:
        print("存在失败项, 请按上方提示安装依赖后重试 (详见 docs/INSTALL.md)。")

    if "--write" in sys.argv:
        os.makedirs("data", exist_ok=True)
        with open(os.path.join("data", "compat_report.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(f"{lv} {it}  {d}".rstrip() for lv, it, d in results))
        print("报告已保存: data/compat_report.txt")


if __name__ == "__main__":
    main()
