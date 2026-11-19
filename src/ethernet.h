#ifndef NPCAP_ETHERNET_H
#define NPCAP_ETHERNET_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

/*
 * Ethernet II 帧解析
 * -----------------
 * 只负责“把原始字节解释成字段”，不依赖 pcap，便于单独测试。
 *
 * 经典 Ethernet II 帧头共 14 字节：
 *
 *   0               6               12      14
 *   +---------------+---------------+-------+----------------------+
 *   | 目的 MAC (6B) | 源 MAC (6B)   | 类型  | 负载（类型字段之后） |
 *   +---------------+---------------+-------+----------------------+
 *
 * 本实验要求显示：
 *   1. 源 MAC 地址（6 字节）
 *   2. 目的 MAC 地址（6 字节）
 *   3. 类型字段的值（2 字节，网络字节序）
 *   4. 类型字段之后第一个字节的值
 */
namespace ethernet {

inline constexpr std::size_t kMacLength = 6;
inline constexpr std::size_t kHeaderLength = 14;

using MacAddress = std::array<std::uint8_t, kMacLength>;

struct FrameView {
    MacAddress destination{};
    MacAddress source{};
    std::uint16_t type = 0;       // 已转换为主机字节序
    bool has_payload = false;     // caplen > 14 时为 true
    std::uint8_t first_payload_byte = 0;
    std::size_t payload_offset = kHeaderLength;
};

/*
 * 解析一个 Ethernet II 帧。
 *
 * 返回值：
 *   true  - 至少有 14 字节，MAC 与类型字段有效；不足 15 字节时
 *           has_payload 为 false。
 *   false - 数据不足 14 字节，error 中给出原因。
 */
bool parse(const std::uint8_t *data, std::size_t caplen, FrameView &frame,
           std::string &error);

std::string mac_to_string(const MacAddress &mac);

/* 返回类型字段的协议名；无法识别时返回 "Unknown"。 */
const char *type_name(std::uint16_t type);

} // namespace ethernet

#endif // NPCAP_ETHERNET_H
