"""Windows 移动热点管理.

通过 PowerShell (5.1) 调用 WinRT API:
  Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager
这是 Windows 10/11 "设置 -> 网络 -> 移动热点" 背后使用的同一套 API。

注意:
  - 所有命令以 Base64(UTF-16LE) 编码传给 powershell, 规避引号/转义/编码问题
  - 需要至少一块已联网的网卡作为共享源 (GetInternetConnectionProfile)
  - 部分操作需要管理员权限
"""
import base64
import json
import subprocess

PS_PREFIX = (
    "$ErrorActionPreference='Stop';"
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
)

# WinRT 异步操作转同步的辅助函数 (Windows PowerShell 5.1 专用技巧)
PS_HELPERS = r"""
function Await($Op, $Type) {
  $asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
    $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
    $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
  $netTask = $asTask.MakeGenericMethod($Type).Invoke($null, @($Op))
  $netTask.Wait(-1) | Out-Null
  $netTask.Result
}
function AwaitAction($Act) {
  $asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
    $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and !$_.IsGenericMethod })[0]
  $netTask = $asTask.Invoke($null, @($Act))
  $netTask.Wait(-1) | Out-Null
}
Add-Type -AssemblyName System.Runtime.WindowsRuntime | Out-Null
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function Get-Mgr {
  $profile = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()
  if (-not $profile) { throw 'NO_INTERNET_PROFILE: 没有找到可共享的网络连接' }
  [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile($profile)
}
"""

# 操作状态枚举
STATE_NAMES = {
    0: "Unknown(未知)",
    1: "On(已开启)",
    2: "Off(已关闭)",
    3: "InTransition(切换中)",
    4: "Unavailable(不可用)",
    5: "Initializing(初始化中)",
}


def _b64(ps: str) -> str:
    return base64.b64encode(ps.encode("utf-16-le")).decode("ascii")


def _run_ps(script: str, timeout: int = 60):
    """执行 PowerShell, 返回 (stdout, stderr, returncode)."""
    cmd = [
        "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-EncodedCommand", _b64(script),
    ]
    try:
        # CREATE_NO_WINDOW: GUI(无控制台)模式下防止每次调用弹出黑色窗口
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        out = p.stdout.decode("utf-8", errors="replace").strip()
        err = p.stderr.decode("utf-8", errors="replace").strip()
        # Windows 控制台可能残留 BOM/CLIXML
        if out.startswith("\ufeff"):
            out = out[1:]
        return out, err, p.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except FileNotFoundError:
        return "", "powershell not found", -1


class HotspotResult:
    def __init__(self, ok, msg="", data=None):
        self.ok = ok
        self.msg = msg
        self.data = data or {}


def get_status() -> HotspotResult:
    """读取热点状态: 开关/SSID/密码(掩码)/客户端数/最大客户端数."""
    script = PS_HELPERS + """
$m = Get-Mgr
$cfg = $m.GetCurrentAccessPointConfiguration()
[PSCustomObject]@{
  state = [int]$m.TetheringOperationalState
  ssid  = $cfg.Ssid
  key   = $cfg.Passphrase
  clients = $m.ClientCount
  maxClients = $m.MaxClientCount
  band = [string]$cfg.Band
} | ConvertTo-Json -Compress
"""
    out, err, rc = _run_ps(script, timeout=45)
    if rc != 0 or not out:
        return HotspotResult(False, err or "读取热点状态失败")
    try:
        d = json.loads(out)
        d["state_name"] = STATE_NAMES.get(int(d.get("state", 0)), str(d.get("state")))
        return HotspotResult(True, data=d)
    except Exception as e:
        return HotspotResult(False, f"解析状态失败: {e}; raw={out[:200]}")


def configure(ssid: str, password: str, band: str = "Auto", max_clients: int = None) -> HotspotResult:
    """配置热点 SSID / WPA2 密码 / 频段 / (尽力设置)最大客户端数."""
    if not (1 <= len(ssid) <= 32):
        return HotspotResult(False, "SSID 长度需 1-32 字符")
    if not (8 <= len(password) <= 63):
        return HotspotResult(False, "WPA2 密码长度需 8-63 字符")
    band_map = {
        "Auto": "Auto",
        "WiFi24GHz": "WiFi24GHz",
        "WiFi50GHz": "WiFi50GHz",
    }
    band_v = band_map.get(band, "Auto")

    script = PS_HELPERS + f"""
$m = Get-Mgr
$cfg = $m.GetCurrentAccessPointConfiguration()
$cfg.Ssid = '{ssid}'
$cfg.Passphrase = '{password}'
try {{ $cfg.Band = [Windows.Networking.NetworkOperators.TetheringWiFiBand]::{band_v} }} catch {{ }}
AwaitAction ($m.ConfigureAccessPointAsync($cfg))
$maxSet = 'no'
try {{
  $m.MaxClientCount = {int(max_clients) if max_clients else 8}
  $maxSet = 'yes'
}} catch {{ }}
Write-Output ('OK maxSet=' + $maxSet + ' ssid=' + $m.GetCurrentAccessPointConfiguration().Ssid)
"""
    out, err, rc = _run_ps(script, timeout=60)
    ok = rc == 0 and "OK" in out
    return HotspotResult(ok, out if ok else (err or out or "配置失败"),
                         {"max_client_set": "maxSet=yes" in out})


def start() -> HotspotResult:
    script = PS_HELPERS + """
$m = Get-Mgr
if ($m.TetheringOperationalState -eq 'On') { Write-Output 'ALREADY_ON'; exit 0 }
$r = Await ($m.StartTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])
Write-Output ('RESULT status=' + [int]$r.Status + ' extra=' + $r.AdditionalInfo)
"""
    out, err, rc = _run_ps(script, timeout=90)
    if rc == 0 and ("RESULT status=0" in out or "ALREADY_ON" in out):
        return HotspotResult(True, out)
    return HotspotResult(False, err or out or "启动热点失败")


def stop() -> HotspotResult:
    script = PS_HELPERS + """
$m = Get-Mgr
if ($m.TetheringOperationalState -eq 'Off') { Write-Output 'ALREADY_OFF'; exit 0 }
$r = Await ($m.StopTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])
Write-Output ('RESULT status=' + [int]$r.Status + ' extra=' + $r.AdditionalInfo)
"""
    out, err, rc = _run_ps(script, timeout=90)
    if rc == 0 and ("RESULT status=0" in out or "ALREADY_OFF" in out):
        return HotspotResult(True, out)
    return HotspotResult(False, err or out or "关闭热点失败")


# ---------------- 热点虚拟网卡探测 (供抓包/防火墙定位接口) ----------------

PS_FIND_AP_IFACE = """
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$adapters = Get-NetAdapter | Where-Object {
  $_.InterfaceDescription -like '*Microsoft Wi-Fi Direct Virtual*' -and $_.Status -eq 'Up'
}
$result = @()
foreach ($a in $adapters) {
  $ipCfg = Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 |
           Where-Object { $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1
  $result += [PSCustomObject]@{
    alias = $a.Name
    desc  = $a.InterfaceDescription
    guid  = $a.InterfaceGuid
    ifIndex = $a.ifIndex
    mac   = $a.MacAddress
    ip    = if ($ipCfg) { $ipCfg.IPAddress } else { '' }
    prefix = if ($ipCfg) { [int]$ipCfg.PrefixLength } else { 0 }
  }
}
$result | ConvertTo-Json -Compress
"""


def find_ap_interface():
    """探测热点虚拟网卡 (Microsoft Wi-Fi Direct Virtual Adapter).

    返回 dict 或 None: {alias, desc, guid, ifIndex, mac, ip, prefix}
    guid 形如 {4D36E972-...} (无花括号), 与 Scapy 的接口 GUID 匹配.
    """
    out, err, rc = _run_ps(PS_FIND_AP_IFACE, timeout=30)
    if rc != 0 or not out:
        return None
    try:
        data = json.loads(out)
        if isinstance(data, list):
            return data[0] if data else None
        return data
    except Exception:
        return None


# ---------------- 管理员权限 / 网卡信息 ----------------

def is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def list_wlan_adapters():
    """列出无线网卡 (netsh wlan show drivers 解析), 判断是否支持热点所需特性."""
    out, err, rc = _run_ps(
        "$ErrorActionPreference='SilentlyContinue';"
        "Get-NetAdapter -Physical | Where-Object {$_.PhysicalMediaType -like '*Native*802*11*' -or $_.Name -eq 'WLAN' -or $_.InterfaceDescription -like '*Wireless*' -or $_.InterfaceDescription -like '*Wi-Fi*'} | "
        "Select-Object Name,InterfaceDescription,Status,MacAddress,ifIndex | ConvertTo-Json -Compress",
        timeout=30)
    if rc != 0 or not out:
        return []
    try:
        data = json.loads(out)
        return data if isinstance(data, list) else [data]
    except Exception:
        return []
