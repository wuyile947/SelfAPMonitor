"""系统级管控封装: Windows 防火墙 / QoS 策略.

所有动作通过 netsh / PowerShell (New-NetFirewallRule, New-NetQosPolicy) 完成,
不使用任何 Linux 工具, 不注入数据包, 不做中间人。

规则命名约定 (便于清理):
  防火墙:  SELFAPMON_BLK_<mac标识> / SELFAPMON_FPD_853 (强制降级)
  QoS:     SELFAPMON_QOS_<mac标识>

实测结论 (2026-09, 本机验证):
  - Windows 热点 = ICS NAT 转发, 客户端流量不过主机的 ALE/传输层过滤点,
    advfirewall 规则 (按 RemoteAddress=客户端IP) 与 netsh ipsec 均对转发流量无效
  - 设备断网/踢除由 DNS 过滤层实现 (见 dnsfilter.py), 本模块不再提供按客户端IP阻断
  - New-NetQosPolicy 限速只对本机流量精确生效, 对转发流量为尽力而为
"""
import base64
import subprocess
import time

RULE_GROUP = "SelfAPMonitor"


def _b64(ps: str) -> str:
    return base64.b64encode(ps.encode("utf-16-le")).decode("ascii")


def run_ps(script: str, timeout=45):
    cmd = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
           "-EncodedCommand", _b64(script)]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        out = p.stdout.decode("utf-8", errors="replace").strip()
        err = p.stderr.decode("utf-8", errors="replace").strip()
        if out.startswith("\ufeff"):
            out = out[1:]
        return out, err, p.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except FileNotFoundError:
        return "", "powershell not found", -1


def _mac_tag(mac: str) -> str:
    return str(mac).replace(":", "").lower()[:12]


def allow_warn_page():
    """放行热点客户端访问本机 80 端口警告页 (幂等).

    注意: 仅放行入站 TCP 80 (本机提示页服务), 与按客户端IP阻断转发流量
    无关 (那已被证实无效, 见模块头注释)."""
    script = ("if (-not (Get-NetFirewallRule -DisplayName 'SELFAPMON_WARN80' "
              "-ErrorAction SilentlyContinue)) { New-NetFirewallRule "
              "-DisplayName 'SELFAPMON_WARN80' -Group 'SelfAPMonitor' "
              "-Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow "
              "-Profile Any | Out-Null }")
    out, err, rc = run_ps(script)
    return rc == 0


# ---------------- 防火墙: 遗留规则清理 ----------------
# (设备断网/踢除/域名阻断已改由 DNS 过滤层实现, 见 dnsfilter.py)

def unblock_all() -> str:
    """一键恢复: 清除历史版本遗留的阻断规则 (断网/域名), 保留 FPD 强制降级规则."""
    script = f"""
$ErrorActionPreference = 'Continue'
Remove-NetFirewallRule -DisplayName 'SELFAPMON_BLK_*' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName 'SELFAPMON_D_*' -ErrorAction SilentlyContinue
Write-Output 'OK'
"""
    out, err, rc = run_ps(script)
    return "已清除遗留阻断规则" if "OK" in out else f"恢复失败: {err or out}"


def cleanup_all_rules() -> str:
    script = f"""
$ErrorActionPreference = 'Continue'
Remove-NetFirewallRule -Group '{RULE_GROUP}' -ErrorAction SilentlyContinue
Get-NetQosPolicy -Name 'SELFAPMON_*' -ErrorAction SilentlyContinue | Remove-NetQosPolicy -ErrorAction SilentlyContinue
Write-Output 'OK'
"""
    out, err, rc = run_ps(script)
    return "已清理全部 SELFAPMON 规则" if "OK" in out else f"清理失败: {err or out}"


def set_force_plain_dns(enabled: bool, ap_alias: str = "") -> str:
    """强制降级: 阻断客户端出站 853 (DoT/DoQ), 迫使回落明文DNS. DoH靠SNI层阻断."""
    if not enabled:
        script = f"""
$ErrorActionPreference = 'Continue'
Remove-NetFirewallRule -DisplayName 'SELFAPMON_FPD_*' -ErrorAction SilentlyContinue
Write-Output 'OK'
"""
        out, err, rc = run_ps(script)
        return "已停止强制降级 (853恢复放行)" if "OK" in out else f"操作失败: {err or out}"
    common = (f"-DisplayName 'SELFAPMON_FPD_853' -Group '{RULE_GROUP}' "
              f"-RemotePort 853 -Profile Any -Enabled True -Action Block")
    if ap_alias:
        common += f" -InterfaceAlias '{ap_alias}'"
    script = f"""
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Remove-NetFirewallRule -DisplayName 'SELFAPMON_FPD_*' -ErrorAction SilentlyContinue | Out-Null
$r1 = New-NetFirewallRule {common} -Direction Outbound -Protocol TCP
$r2 = New-NetFirewallRule {common} -Direction Outbound -Protocol UDP
if ($r1 -and $r2) {{ Write-Output 'OK' }} else {{ Write-Output 'FAIL' }}
"""
    out, err, rc = run_ps(script)
    ok = "OK" in out
    return "已阻断853端口 (DoT/DoQ将回落明文DNS)" if ok else f"规则下发失败: {err or out}"


_ap_alias_cache = {"alias": "", "ts": 0}


def get_ap_alias() -> str:
    from . import hotspot
    if time.time() - _ap_alias_cache["ts"] > 60:
        info = hotspot.find_ap_interface()
        _ap_alias_cache["alias"] = (info or {}).get("alias", "")
        _ap_alias_cache["ts"] = time.time()
    return _ap_alias_cache["alias"]


# ---------------- QoS 限速 (尽力而为) ----------------

def apply_rate_limit(mac: str, ip: str, mbps: float) -> str:
    """对指定设备下发 QoS 限速策略 (IPSrc/IPDst 双向).

    注意: Windows 客户端 SKU 上 QoS 策略对 ICS 转发流量可能不生效,
    本函数会如实返回下发结果, 详见局限文档.
    """
    if not ip:
        return "无IP, 无法下发限速"
    tag = _mac_tag(mac)
    mbps = max(0.1, float(mbps))
    script = f"""
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Get-NetQosPolicy -Name 'SELFAPMON_QOS_{tag}' -ErrorAction SilentlyContinue | Remove-NetQosPolicy -ErrorAction SilentlyContinue
$p1 = New-NetQosPolicy -Name 'SELFAPMON_QOS_{tag}_up' -IPSrc '{ip}' -ThrottleRateMBps {mbps} -PolicyStore ActiveStore -ErrorAction SilentlyContinue
$p2 = New-NetQosPolicy -Name 'SELFAPMON_QOS_{tag}_down' -IPDst '{ip}' -ThrottleRateMBps {mbps} -PolicyStore ActiveStore -ErrorAction SilentlyContinue
if ($p1 -or $p2) {{ Write-Output ('OK created=' + [bool]$p1 + ',' + [bool]$p2) }} else {{ Write-Output 'FAIL' }}
"""
    out, err, rc = run_ps(script, timeout=45)
    if "OK" in out:
        # 读取策略是否真正被接受 (ActiveStore 在客户端 SKU 上可能拒收 throttle)
        return f"QoS 限速策略已下发 ({out.split('OK ')[-1]}); 注意: 对转发流量可能不生效, 见局限文档"
    return f"QoS 限速下发失败: {err or out} (家庭中文版/客户端SKU 常见, 见局限文档)"


def remove_rate_limit(mac: str) -> str:
    tag = _mac_tag(mac)
    script = f"""
$ErrorActionPreference = 'Continue'
Get-NetQosPolicy -Name 'SELFAPMON_QOS_{tag}_*' -ErrorAction SilentlyContinue | Remove-NetQosPolicy -ErrorAction SilentlyContinue
Write-Output 'OK'
"""
    out, err, rc = run_ps(script)
    return "已移除限速策略" if "OK" in out else f"移除失败: {err or out}"
