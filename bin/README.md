# 预编译产物（Windows 11 ARM64）

本目录下的文件是在 **ARM64 Windows 11 + Npcap 1.90** 环境中编译并实机验证过的二进制。
源码与构建方法见仓库根目录的 `README.md`。

| 文件 | 大小 | 说明 |
|---|---:|---|
| `npcap_sniffer_arm64.exe` | 836,096 B | 主程序，ARM64（AArch64） |
| `wpcap.dll` | 495,032 B | Npcap 的 libpcap 兼容 DLL（ARM64） |
| `Packet.dll` | 213,432 B | Npcap 驱动访问 DLL（ARM64） |

## 运行

1. 先在这台 Windows 机器上安装 Npcap 1.90（或兼容版本）。
2. 把三个文件放在同一目录，**以管理员身份**打开终端运行：

   ```bat
   npcap_sniffer_arm64.exe --list
   npcap_sniffer_arm64.exe
   ```

   系统已安装 Npcap 时，程序会优先加载 `C:\Windows\System32\Npcap` 下的 DLL；
   否则会使用同目录下的这两个 DLL。

## SHA-256

```text
5e224126c84aa25ef063e64d407af7749eeb104152d9a4f840192701ee33a3c8  npcap_sniffer_arm64.exe
ac1cdc6c988c965db4469f327b9cf9d87b6ecaa123bf135d7db20de88b456688  wpcap.dll
3590e7a772207c6cdede4a5d1507ce68d44d12007fc7b07d988d84d53ede3a63  Packet.dll
```

`wpcap.dll` 与 `Packet.dll` 来自 Npcap 1.90（Nmap Project），版权归其作者所有，
此处仅作为本实验的运行依赖一并提供；正式分发请遵循 Npcap 的许可条款。
