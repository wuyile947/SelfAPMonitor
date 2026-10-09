"""E2E 测试: DNSFilter 绑定热点网关:53 + 设备级断网 (纯本机验证, 不注入任何包).

用法: python test_dnsblock_e2e.py [手机IP, 默认 192.168.137.148]
"""
import re
import subprocess
import sys
import time

sys.path.insert(0, ".")
from selfapmon import hotspot, dnsfilter
from selfapmon.config import Config

PHONE_IP = sys.argv[1] if len(sys.argv) > 1 else "192.168.137.148"


def nslookup(name, server="192.168.137.1"):
    p = subprocess.run(["nslookup", name, server], capture_output=True, timeout=8,
                       creationflags=subprocess.CREATE_NO_WINDOW)
    out = p.stdout.decode("gbk", "replace")
    ips = [m.group(1) for m in re.finditer(r"Address(?:es)?\s*[:=]?\s*([\d.]+)", out)
           if m.group(1) != server]
    return ips, out


blocked_log = []


def cb(qname, rule, src_ip):
    blocked_log.append((qname, rule, src_ip))


info = hotspot.find_ap_interface()
ap_ip = (info or {}).get("ip", "")
print(f"[1] 热点网关: {info}")
assert ap_ip, "热点未开启, 无法测试"

cfg = Config()
dfs = dnsfilter.DNSFilter(cfg, blocked_cb=cb)
dfs.ap_ip_fn = lambda: ap_ip
ups = sorted({s for v in dnsfilter.get_upstreams().values()
              for s in v if s and s != "127.0.0.1"})
dfs.upstreams = ups
print(f"[2] 上游: {ups[:3] or 'fallback'}")
dfs.start()
time.sleep(1.0)
assert dfs.is_alive() and dfs.bound_ip == ap_ip, f"绑定失败: bound={dfs.bound_ip}"
print(f"[2] 绑定成功: {dfs.bound_ip}:53")

# A. 正常转发
ips, raw = nslookup("www.baidu.com")
print(f"[3] 转发 www.baidu.com -> {ips}")
assert ips and "0.0.0.0" not in ips, "转发失败:\n" + raw

# B. 设备断网 (把本机在热点上的源IP加入名单 -> 同一代码路径)
dfs.set_blocked_ips({ap_ip})
time.sleep(0.2)
ips, raw = nslookup("www.baidu.com")
print(f"[4] 名单含本机源IP -> {ips}")
assert "0.0.0.0" in ips, "设备断网拦截失败:\n" + raw

# C. 移除 -> 恢复
dfs.set_blocked_ips(set())
time.sleep(0.2)
ips, raw = nslookup("www.baidu.com")
print(f"[5] 移除后恢复 -> {ips}")
assert ips and "0.0.0.0" not in ips, "恢复失败:\n" + raw

# D. 被动观察手机: 加入名单 60 秒, 手机后台自然产生DNS查询
dfs.set_blocked_ips({PHONE_IP})
print(f"[6] 已把 {PHONE_IP} 加入断网名单, 被动观察 60 秒...")
t0 = time.time()
while time.time() - t0 < 60:
    time.sleep(5)
    hits = [x for x in blocked_log if x[2] == PHONE_IP]
    tail = f" 例: {hits[-1][0]}" if hits else ""
    print(f"    {int(time.time() - t0)}s: 已拦截 {len(hits)} 条{tail}")
dfs.set_blocked_ips(set())
hits = [x for x in blocked_log if x[2] == PHONE_IP]
dfs.stop()
print(f"[7] 60秒内拦截 {PHONE_IP} 共 {len(hits)} 条DNS查询")
if hits:
    print(f"    域名样例: {sorted({h[0] for h in hits})[:10]}")
print("RESULT:", "PHONE_BLOCKED_OK" if hits else "PHONE_NO_DNS_SEEN (60秒内该手机无DNS查询)")
