# SelfAPMonitor

**Windows 自带移动热点的家庭网络管控工具**
*Home network management & parental-control tool for the Windows built-in mobile hotspot.*

[简体中文](#简体中文) | [English](#english)

---

<a id="简体中文"></a>
## 简体中文

SelfAPMonitor 是一个纯本地运行的 Windows 桌面程序，用于管理和观测**由你本人开启的 Windows 移动热点**：查看哪些设备接入了你的热点、各设备用了多少流量、设置流量配额与上网规则、对未成年人做上网时间与内容的访问控制（家长防沉迷）。

- **原生界面**：Python + Tkinter，无 Web 服务、无浏览器页面，可打包为单文件 EXE
- **纯本地运行**：所有数据保存在本机 SQLite，不上传任何服务器，无云端账号
- **只观测元数据**：被动抓包，仅读取五元组、包长、DNS 查询名、TLS 握手中的明文字段（SNI/ALPN/JA3），**不解密通信内容、不做中间人、不伪造证书**

### 适用场景

- 家庭网络管理：查看谁连了家里的热点、各设备流量消耗
- 家长控制：给孩子的设备设置流量配额、屏蔽短视频与广告 SDK 域名
- 自有网络的访问控制：黑名单设备接入时自动断网并提醒
- 网络学习：Windows ICS/移动热点转发机制、DNS、TLS/QUIC 握手的实验与研究

### 功能一览

| 类别 | 功能 |
|------|------|
| 热点管理 | 启停 Windows 自带移动热点、配置 SSID / WPA2 密码 / 频段 / 最大连接数（WinRT 官方接口） |
| 设备观测 | 接入设备列表、在线状态、上下行流量、实时速率、陌生设备弹窗告警 |
| 元数据解析 | 明文 DNS 查询记录、TLS ClientHello（SNI/ALPN/版本/JA3）、ECH/加密 DNS 仅做标记、可选 nDPI 协议识别 |
| 流量配额 | 按设备设置流量上限，90% 预警、超限自动断网（可关闭） |
| 访问控制 | 域名黑名单、短视频 App 域名屏蔽、广告 SDK 域名屏蔽、按流量类型阻断、黑名单设备自动断网 |
| 管控手段 | DNS 解析拦截、TCP RST/QUIC VN 连接终止报文、ARP 回程黑洞、断网警告页（Captive Portal 提示页） |
| 数据导出 | DNS 记录 / 会话 / 设备上下线 / 事件日志导出为 CSV |
| 数据存储 | 本地 SQLite，自动按天数与容量清理 |

### 管控是如何实现的（请务必阅读）

Windows **没有提供**"断开某个热点客户端"的公开 API。本软件的所有管控动作都只作用于**本软件自己开启的热点**，通过系统机制实现：

1. **DNS 解析拦截**：对命中规则的域名返回阻断应答（仅返回解析结果，不转发查询内容）
2. **协议内连接终止报文**（可选，默认开关可控）：对命中规则的连接发送协议规范内的 TCP RST 与 QUIC Version Negotiation 报文，终止连接建立，用于补上 App 内置 HTTPDNS 硬编码 IP 直连对 DNS 拦截的绕过。不伪造业务数据、不篡改通信内容；QUIC Initial 报文按 RFC 规范以公开算法加密，仅读取其中的明文 SNI
3. **ARP 邻居表回程黑洞**（可选，默认开启）：把断网设备写入本机邻居表的静态黑洞条目，使其收不到任何回程包，用于杀死协议内无法终止的**已建立 QUIC 连接**；只改本机系统表，不触碰设备
4. **断网警告页**：被限制设备访问明文 HTTP 站点时，显示中文"网络访问已受限"提示页（防火墙仅用于放行该页面的 80 端口入站；按 IP 阻断转发流量实测无效，已不采用）
5. **热点重启**：Windows 唯一能确定性清空所有已连接客户端会话的手段

各手段的生效边界（例如 QoS 限速对热点转发流量不保证生效、已建立的 QUIC 连接无法协议内终止等）在 [docs/WINDOWS_LIMITATIONS.md](docs/WINDOWS_LIMITATIONS.md) 中如实记录。

### 快速开始

```powershell
# 1. 安装依赖（唯一必须的 pip 包；另需安装 Npcap 驱动）
pip install "scapy>=2.5.0" cryptography

# 2. 以管理员身份运行
python main.py
```

完整安装步骤（含 Npcap、nDPI、EXE 打包）见 [docs/INSTALL.md](docs/INSTALL.md)，
界面操作说明见 [docs/USAGE.md](docs/USAGE.md)。

### 系统要求

- Windows 10 1903+ / Windows 11（需系统自带"移动热点"功能）
- Python 3.10–3.13（3.14 需 Scapy ≥ 2.5.0）
- 管理员权限；一块已联网的无线网卡
- [Npcap](https://npcap.com/)（抓包底层驱动，需单独安装）
- nDPI 为可选依赖，不安装时自动退回内置启发式识别

### 法律与使用边界

本软件**仅限在本人所有或本人有权管理的设备与网络上使用**，用于家庭网络管理与家长控制。

- 只采集网络元数据，不解析任何加密通信内容
- 管控动作仅作用于自己开启的热点，属于对自有网络的访问控制
- 未经授权监控、干扰他人设备或网络，可能违反《中华人民共和国网络安全法》《个人信息保护法》及《刑法》相关条款，以及使用者所在地法律，责任由使用者自行承担
- 程序首次启动强制显示完整法律声明，不同意则不得使用

### 免责声明

本软件为个人学习与家庭自用项目，按"现状"提供，不提供任何明示或暗示的担保。Windows 各版本、网卡与安全软件环境差异较大，部分功能为尽力而为（详见局限文档）。请在合法合规的前提下使用；因滥用造成的一切后果由使用者承担。

### 许可证

[MIT License](LICENSE)

---

<a id="english"></a>
## English

SelfAPMonitor is a fully local Windows desktop application for managing and observing the **Windows built-in mobile hotspot that you yourself turn on**: see which devices are connected, how much traffic each device uses, set traffic quotas and access rules, and apply parental controls (e.g. blocking short-video apps) on your own network.

- **Native UI**: Python + Tkinter. No web server, no browser UI. Can be packaged as a single-file EXE.
- **100% local**: all data is stored in a local SQLite database. No cloud account, no data upload.
- **Metadata only**: passive sniffing of five-tuples, packet sizes, plaintext DNS names and cleartext TLS handshake fields (SNI/ALPN/JA3). It **never decrypts traffic content, never performs MITM, and never forges certificates**.

### Use cases

- Home network management: see who is on your hotspot and how much traffic they use
- Parental controls: per-device traffic quotas, short-video and ad-domain blocking
- Access control on your own network: auto-block and alert on blacklisted devices
- Research/education: Windows ICS & mobile-hotspot forwarding, DNS, TLS/QUIC handshakes

### Features

- Start/stop the Windows mobile hotspot and configure SSID / WPA2 password / band / max clients via the official WinRT API
- Connected-device list, online status, per-device traffic stats and real-time rate chart, unknown-device alerts
- Plaintext DNS logging; TLS ClientHello metadata (SNI/ALPN/version/JA3); ECH/encrypted-DNS marked but not decrypted; optional nDPI integration
- Per-device traffic quotas (90% warning, automatic cut-off when exceeded)
- Domain blacklist, built-in short-video and ad-SDK domain blocking, category-based blocking
- Control mechanisms: DNS response filtering, TCP RST / QUIC VN connection-termination packets, an ARP-neighbor return-route blackhole, and a captive-portal-style warning page (see below)
- CSV export; local SQLite storage with automatic retention cleanup

### How enforcement works (please read)

Windows provides **no public API to disconnect an individual hotspot client**. Every enforcement action in this program applies only to **the hotspot started by this program itself**:

1. **DNS response filtering** — block answers for domains matching your rules
2. **In-protocol connection-termination packets** (optional, toggleable): standards-compliant TCP RST and QUIC Version Negotiation packets that stop a rule-matching connection from being established. They also close the bypass where apps use hardcoded-IP HTTPDNS instead of system DNS. No application data is forged or modified. QUIC Initial packets use the public-key scheme defined by the RFC; only the cleartext SNI is read
3. **ARP-neighbor return-route blackhole** (optional, enabled by default): a blocked device is written into the local machine's neighbor table as a static blackhole entry, so it receives no return traffic at all. This kills **already-established QUIC connections**, which cannot be terminated in-protocol. Only the local machine's system table is touched; the client device is never modified
4. **Warning page** — restricted devices see a local "network access restricted" page on plaintext HTTP sites. (The firewall is used only to allow inbound TCP 80 for this page; per-IP blocking of forwarded traffic proved ineffective in testing and is not used.)
5. **Hotspot restart** — the only deterministic way Windows offers to clear all existing client sessions

Known boundaries (e.g. QoS throttling is not guaranteed for forwarded traffic; already-established QUIC connections cannot be terminated in-protocol) are documented honestly in [docs/WINDOWS_LIMITATIONS.md](docs/WINDOWS_LIMITATIONS.md).

### Quick start

```powershell
# 1. Install Python deps (Npcap driver must also be installed separately)
pip install "scapy>=2.5.0" cryptography

# 2. Run as Administrator
python main.py
```

Full setup (Npcap, nDPI, EXE packaging): [docs/INSTALL.md](docs/INSTALL.md) ·
Usage guide: [docs/USAGE.md](docs/USAGE.md)

### Requirements

- Windows 10 1903+ / Windows 11 with the built-in Mobile Hotspot feature
- Python 3.10–3.13 (3.14 requires Scapy ≥ 2.5.0)
- Administrator privileges; one Internet-connected Wi-Fi adapter
- [Npcap](https://npcap.com/) (mandatory packet-capture driver, installed separately)
- nDPI is optional; the built-in heuristic engine is used without it

### Legal & acceptable use

This software may **only be used on devices and networks that you own or are authorized to manage**, for home-network management and parental-control purposes.

- It collects network metadata only and never decrypts communication content.
- Enforcement applies solely to the hotspot you started yourself and constitutes access control on your own network.
- Monitoring or interfering with devices/networks without authorization may violate the cybersecurity and privacy laws of your jurisdiction. You are solely responsible for your use of this software.
- A full legal notice is displayed on every startup; the software must not be used unless accepted.

### Disclaimer

This is a personal, home-use project provided **"as is"**, without warranty of any kind. Windows editions, adapters and security software vary widely, and some features are best-effort (see the limitations document). Use it only in compliance with applicable law; you bear all responsibility for any misuse.

### License

[MIT License](LICENSE)
