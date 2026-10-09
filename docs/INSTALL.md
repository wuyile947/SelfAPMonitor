# Self-AP-Monitor 依赖安装文档 (Windows 10/11)

> 法律边界：本工具仅限在本人所有或有权管理的设备/网络上做元数据观测与本地管控。
> **不解密 HTTPS、不做中间人、不伪造证书**；管控动作含 DNS 解析拦截与协议内
> 连接终止报文（TCP RST / QUIC VN），仅作用于本软件自己开启的热点。
> 详见 `selfapmon/legal.py`。

## 1. 系统要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Windows 10 1903+ / Windows 11 （需自带"移动热点"功能）|
| Python | 3.10 – 3.13 均可；3.14 需 Scapy ≥ 2.5.0 |
| 权限 | **管理员**（防火墙/QoS/抓包均需要；热点配置最好也有）|
| 硬件 | 一块已联网的无线网卡（热点共享源）+ 系统创建的 Wi-Fi Direct 虚拟适配器 |

## 2. 安装步骤

### 2.1 Python（官方安装器，不要用 Store 版）
1. 下载 https://www.python.org/downloads/windows/
2. 安装时勾选：
   - ✅ `Add python.exe to PATH`
   - ✅ `tcl/tk and IDLE`（Tkinter，默认已勾选）

### 2.2 Python 依赖（Scapy + cryptography）
```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
# 或手动: pip install "scapy>=2.5.0" cryptography
```
`cryptography` 用于 QUIC Initial 报文的公开算法解析（HKDF/AES-GCM，
仅读取明文 SNI，不解密任何通信内容）。

### 2.3 Npcap（Scapy 在 Windows 抓包的底层驱动，**必须**）
1. 下载 https://npcap.com/#download （`npcap-1.x.exe`）
2. 安装选项：
   - ✅ `Install Npcap in WinPcap API-compatible Mode`
   - ✅ `Support raw 802.11 traffic`（可选，开启 monitor 模式）
   - 勾选 `Restrict Npcap driver's access to Administrators only` 时，本程序必须以管理员运行

### 2.4 nDPI（**可选**，提升协议识别精度；不装则自动退回内置启发式识别）
两条路任选其一：

**A. MSYS2 预编译（最快）**
```powershell
# 安装 MSYS2: https://www.msys2.org/
pacman -S mingw-w64-x86_64-ndpi
# 把 dll 拷到本项目 bin\ 下
copy C:\msys64\mingw64\bin\libndpi-*.dll  .\bin\libndpi.dll
```

**B. 自行编译（最灵活）**
```powershell
git clone https://github.com/ntop/nDPI
cd nDPI
# 需 MSVC 或 MinGW + CMake
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
copy build\libndpi.dll  ..\selfapmon-monitor\bin\
```

程序启动时按顺序搜索：`config.ndpi_dll_path` → `./bin/libndpi*.dll` → PATH 中的 `libndpi*.dll`。
找不到不影响主流程，DPI 引擎自动退回启发式（SNI 关键词 + 端口/明文载荷特征）。

### 2.5 标准库（无需 pip）
`tkinter / sqlite3 / subprocess / csv / threading / queue / json / re / time / os / ipaddress / collections / ctypes / base64 / struct / hashlib`

## 3. 一键环境自检

```powershell
python check_compatibility.py --write
```
脚本只读检测 11 项：OS / Python / tkinter / 管理员 / 无线网卡 / Wi-Fi Direct 虚拟适配器 /
icssvc & SharedAccess 服务 / WinRT 热点 API / Npcap / Scapy / 防火墙与 QoS cmdlet / nDPI。
报告同时写入 `data/compat_report.txt`。

## 4. 打包为 EXE（可选）

```powershell
pip install pyinstaller
build_exe.bat        # 或手动: python -m PyInstaller --noconfirm --clean --onefile --uac-admin --windowed --name SelfAPMonitor --collect-all scapy --collect-all cryptography main.py
```
- 产物：`dist\SelfAPMonitor.exe`（单文件约 12MB，双击启动自动请求管理员权限/UAC）
- `data\`（配置与数据库）生成在 **exe 同目录**，可随 exe 拷贝迁移
- EXE 用户仍需**自行安装 Npcap**（驱动无法打包进 exe）
- 首次启动慢 2-5 秒属正常（onefile 自解压）；杀软可能误报加壳，需自行加白
- 若 bin\ 下有 libndpi.dll，打包脚本会自动并入

## 5. 启动

```powershell
# 必须以管理员身份运行（右键 PowerShell -> 以管理员身份运行）
python main.py
```
启动流程：
1. 法律与安全使用声明弹窗 → 点"我已阅读并同意"
2. 若非管理员 → 提示以管理员身份重启 / 或继续受限模式
3. 进入主界面；若热点已开启，自动开始抓包

## 5. 卸载
```powershell
# 清理本程序创建的防火墙/QoS规则（退出时已自动清理，此处兜底）
powershell -Command "Remove-NetFirewallRule -Group SelfAPMonitor -ErrorAction SilentlyContinue;
                     Get-NetQosPolicy -Name 'SELFAPMON_*' -ErrorAction SilentlyContinue | Remove-NetQosPolicy"
# 删除项目目录与数据
rmdir /s /q selfapmon-monitor
```
Npcap 卸载：控制面板 → 程序 → Npcap → 卸载。

## 6. 常见问题

| 现象 | 原因 / 解决 |
|------|------|
| 抓包启动失败 "Scapy 不可用" | `pip install scapy` |
| 抓包启动失败 "未找到热点虚拟网卡" | 先在主界面点"启动热点"，等 Wi-Fi Direct 虚拟适配器出现 |
| "powershell 执行策略禁止" | 程序已用 `-ExecutionPolicy Bypass`，若仍报错改用管理员身份 |
| QoS 限速无效 | 家庭中文版/客户端 SKU 常见，见 `WINDOWS_LIMITATIONS.md` |
| 中文 PowerShell 输出乱码 | 程序已强制 UTF-8；若残留，关闭其他 PowerShell 窗口后重试 |
| nDPI 加载后立即退回启发式 | dll ABI 不兼容；删 dll 或换对应版本（见上文编译说明）|
