# 基于 NPcap 的以太网帧捕获程序（C++17）

本程序使用 NPcap 的 libpcap 兼容 API 捕获本机网卡上的数据帧，并在终端实时显示：

- 源 MAC 地址；
- 目的 MAC 地址；
- 以太网类型/长度字段的值及协议名；
- 类型字段之后第一个字节的十六进制值和十进制值。

程序不把抓到的数据包写入磁盘，只在屏幕上按行显示，并在退出时给出捕获/丢弃统计。
完整实验报告见 [`docs/report.md`](docs/report.md)，Windows 实机验证记录见
[`docs/live-capture.txt`](docs/live-capture.txt)。

## 功能与实验要求对应

| 实验要求 | 实现 |
|---|---|
| 了解 NPcap 架构 | 报告第 3 章；代码只使用其用户态 libpcap API |
| 获取设备列表 | `pcap_findalldevs`，`--list` 或启动时选择 |
| 打开网卡 | `pcap_open_live`，支持混杂模式、snaplen、超时 |
| 捕获数据包 | `pcap_next_ex` 循环；支持 BPF 过滤和帧数限制 |
| 显示源/目的 MAC、类型字段、类型后首字节 | `ethernet::parse` + 终端表格 |
| 不写硬盘、屏幕显示 | 正常模式无任何文件写入；`-r` 仅用于离线验证 |
| 结构清晰、可读性 | 设备/捕获层、帧解析层、命令行与显示层分离 |

## 目录结构

```text
.
├── CMakeLists.txt          # Windows（NPcap SDK）/ macOS/Linux（libpcap）构建
├── Makefile                # macOS/Linux 快速构建与单元测试
├── README.md
├── src/
│   ├── main.cpp            # 命令行、设备选择、显示与捕获循环
│   ├── capture.h/.cpp      # pcap 设备枚举、打开、BPF 过滤、收包封装
│   └── ethernet.h/.cpp     # Ethernet II 帧解析、MAC/类型格式化
├── tests/
│   └── ethernet_tests.cpp  # 不依赖网卡的帧解析单元测试
├── bin/                    # 预编译的 Windows 11 ARM64 产物（见 bin/README.md）
└── docs/
    ├── report.md           # 实验报告
    └── live-capture.txt    # Windows 11 + NPcap 1.90 实机输出
```

## 预编译产物

[`bin/`](bin/) 中提供了在 **ARM64 Windows 11 + Npcap 1.90** 上编译并实机验证过的：

```text
bin/npcap_sniffer_arm64.exe   # 主程序（ARM64）
bin/wpcap.dll                 # Npcap libpcap 兼容 DLL
bin/Packet.dll                # Npcap 驱动访问 DLL
```

文件大小、用法和 SHA-256 校验和见 [`bin/README.md`](bin/README.md)。

## Windows 构建（目标平台）

### 1. 安装 NPcap

从 <https://npcap.com/#download> 下载并安装 NPcap（本实验使用 1.90）。
安装程序需要管理员权限；默认选项即可。NPcap 的 DLL 通常位于
`C:\Windows\System32\Npcap\`。

> 如果机器上同时装过 WinPcap，建议在 NPcap 安装时选择
> “Install Npcap in WinPcap API-compatible Mode”，或确保程序加载的是 NPcap 的
> `wpcap.dll`。

### 2. 下载 NPcap SDK

从 <https://npcap.com/#download> 下载 `npcap-sdk-*.zip`，解压到例如
`C:\npcap-sdk-1.17`。目录中应包含：

```text
Include\pcap.h
Lib\x64\wpcap.lib
Lib\ARM64\wpcap.lib
```

### 3. 使用 CMake 构建

在 “x64 Native Tools Command Prompt for VS 2022” 或普通 PowerShell 中：

```bat
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 ^
      -DNPCAP_SDK_DIR="C:/npcap-sdk-1.17"
cmake --build build --config Release
```

生成：

```text
build\Release\npcap_sniffer.exe
```

ARM64 Windows 把 `-A x64` 换成 `-A ARM64` 即可，CMake 会选择
`Lib\ARM64\wpcap.lib`。

如果使用 MinGW-w64，也可以直接编译：

```bash
x86_64-w64-mingw32-g++ -std=c++17 -O2 -Isrc -IC:/npcap-sdk-1.17/Include \
  src/main.cpp src/capture.cpp src/ethernet.cpp \
  -LC:/npcap-sdk-1.17/Lib/x64 -lwpcap -lws2_32 \
  -static-libgcc -static-libstdc++ -o npcap_sniffer.exe
```

### 4. 运行

**以管理员身份**打开终端，否则 NPcap 可能拒绝打开网卡：

```bat
cd build\Release
npcap_sniffer.exe --list
npcap_sniffer.exe
```

不指定 `-i` 时，程序会先列出设备并提示选择编号。也可以用 `-i` 直接指定编号
（从 1 开始）、pcap 设备名或网卡描述：

```bat
npcap_sniffer.exe -i 4 -c 20 -f "arp or icmp"
npcap_sniffer.exe -i "\Device\NPF_{...}" -c 10
npcap_sniffer.exe -i "Intel(R) Wi-Fi 6 AX201 160MHz" -c 10
```

程序运行期间按 `Ctrl+C` 可停止并输出统计。

### 命令行选项

```text
-l, --list               列出捕获设备后退出
-i, --interface <sel>    设备编号（1 起）或 pcap 设备名；省略则交互选择
-c, --count <n>          抓到 n 帧后停止；0 表示不限制
-f, --filter <expr>      BPF 过滤表达式，例如 "arp or ip"
-r, --read <file>        从 pcap/pcapng 文件回放（仅离线验证用）
-s, --snaplen <n>        每个包最多捕获的字节数，默认 65535
-p, --no-promisc         关闭混杂模式
-t, --timeout-ms <n>     读超时，默认 500 ms
-h, --help               显示帮助
```

## 输出示例

以下为 Windows 11 + NPcap 1.90 实机抓取 ping 流量的输出（完整记录见
`docs/live-capture.txt`）：

```text
Device         : \Device\NPF_{7C348835-3C2D-4EEB-BC00-2D657AD089D3}
Description    : Parallels VirtIO Ethernet Adapter
Data link type : EN10MB (Ethernet)
Promiscuous    : yes
BPF filter     : icmp
Frame limit    : 10

Capturing...

 No.  Time          Source MAC         Destination MAC    EtherType  Protocol            First byte
----  ------------  -----------------  -----------------  ---------  ------------------  ----------
   1  22:14:31.707  00:1c:42:53:17:d5  00:1c:42:00:00:18  0x0800     IPv4                0x45 ( 69)
   2  22:14:31.708  00:1c:42:00:00:18  00:1c:42:53:17:d5  0x0800     IPv4                0x45 ( 69)
...
--- Capture summary ---
Frames read       : 10
Frames displayed  : 10
Malformed frames  : 0
Packets received  : 10
Packets dropped   : 0
Interface dropped : 0
```

各列含义：

- `Source MAC` / `Destination MAC`：以太网帧偏移 6 和 0 处的 6 字节地址；
- `EtherType`：偏移 12 的 2 字节类型/长度字段，按网络字节序解释；
- `Protocol`：常见类型对应的协议名；
- `First byte`：偏移 14 处的第一个字节，例如 IPv4 首字节 `0x45`（版本 4、首部
  长度 5），ARP 首字节 `0x00`。

## 测试

帧解析部分与网卡无关，可以在 macOS/Linux 上直接测试：

```bash
make test
# 或者
cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure
```

测试覆盖 IPv4、ARP、IPv6、VLAN、IEEE 802.3 长度字段、未知类型、截断帧、
无负载帧和 MAC 格式化。Windows 实机验证使用 NPcap 1.90 抓取 ICMP 与 ARP，
输出见 `docs/live-capture.txt`。

离线回放只用于没有网卡权限时检查显示逻辑，例如：

```bash
npcap_sniffer -r demo.pcap -c 5
```

## 常见问题

| 现象 | 处理 |
|---|---|
| `no capture devices found` | 确认已安装 NPcap；以管理员身份运行；`sc query npcap` 应显示 `RUNNING` |
| 打开设备提示 `Permission denied` | 以管理员身份运行；检查 NPcap 安装时是否限制为管理员访问 |
| 找不到 `wpcap.dll` | 确认 `C:\Windows\System32\Npcap` 在 `PATH` 中，或把 `wpcap.dll`/`Packet.dll` 放到 exe 同目录 |
| 选中 `NPF_Loopback` 后提示不是 Ethernet | 回环链路使用 `DLT_NULL`，没有 MAC 头；请选择物理以太网/Wi-Fi 网卡 |
| 抓不到任何包 | 先用 `-f icmp` 并在另一个窗口 `ping` 网关；Wi-Fi 默认是伪以太网头，混杂模式也不等于监听模式 |
| Wi-Fi 只能看到自己的流量 | 普通网卡受 AP 转发限制；需要监听模式时安装 NPcap 时勾选 raw 802.11 并使用 `WlanHelper` |

## 说明

- NPcap 只支持 Windows；macOS/Linux 上使用系统自带或包管理器安装的 libpcap，
  代码使用同一套 libpcap API，便于开发和解析测试。
- `-r` 仅用于离线回放验证，正常抓包路径不创建、不写入任何抓包文件。
- 请只捕获你有权分析的网络流量，遵守实验室和网络管理规定。
