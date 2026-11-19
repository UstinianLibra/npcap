#ifndef NPCAP_CAPTURE_H
#define NPCAP_CAPTURE_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <pcap.h>

/*
 * libpcap / Npcap 用户态接口的薄封装
 * ----------------------------------
 * 本层只处理：
 *   - 设备枚举（pcap_findalldevs）
 *   - 打开网卡（pcap_open_live）或离线文件（pcap_open_offline）
 *   - 安装 BPF 过滤器（pcap_compile + pcap_setfilter）
 *   - 读取数据包（pcap_next_ex）
 *
 * 帧内容如何解释由 ethernet 模块负责，命令行交互由 main 负责，
 * 三层职责分离，便于阅读和单独测试。
 */
namespace capture {

struct Device {
    std::string name;        // pcap 设备名，如 \Device\NPF_{GUID}
    std::string description; // 网卡描述，可能为空
    bool loopback = false;
    bool up = false;
    bool running = false;
};

struct Packet {
    const std::uint8_t *data = nullptr;
    std::uint32_t captured_length = 0; // 实际捕获到的字节数
    std::uint32_t original_length = 0; // 线上原始帧长
    std::int64_t timestamp_sec = 0;
    std::int64_t timestamp_usec = 0;
};

struct Stats {
    std::uint64_t received = 0;
    std::uint64_t dropped = 0;
    std::uint64_t interface_dropped = 0;
};

enum class NextStatus {
    Packet,
    Timeout,
    EndOfFile,
    Error,
};

/* 枚举所有可用的捕获设备。失败时返回 false 并设置 error。 */
bool list_devices(std::vector<Device> &devices, std::string &error);

class Session {
public:
    ~Session();

    Session(const Session &) = delete;
    Session &operator=(const Session &) = delete;

    static std::unique_ptr<Session> open_live(const std::string &device,
                                              int snaplen, bool promiscuous,
                                              int timeout_ms,
                                              std::string &error);
    static std::unique_ptr<Session> open_offline(const std::string &path,
                                                 std::string &error);

    bool set_filter(const std::string &bpf_expression, std::string &error);

    int datalink() const;
    std::string datalink_text() const;

    NextStatus next(Packet &packet, std::string &error);
    bool read_stats(Stats &stats, std::string &error) const;

private:
    explicit Session(pcap_t *handle);

    pcap_t *handle_;
};

} // namespace capture

#endif // NPCAP_CAPTURE_H
