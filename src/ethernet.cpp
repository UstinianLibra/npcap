#include "ethernet.h"

#include <algorithm>
#include <cstdio>

namespace ethernet {

namespace {

std::uint16_t read_be16(const std::uint8_t *p)
{
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) |
                                      static_cast<std::uint16_t>(p[1]));
}

} // namespace

bool parse(const std::uint8_t *data, std::size_t caplen, FrameView &frame,
           std::string &error)
{
    if (data == nullptr) {
        error = "null packet data";
        return false;
    }
    if (caplen < kHeaderLength) {
        error = "frame too short: " + std::to_string(caplen) +
                " bytes, need at least " + std::to_string(kHeaderLength);
        return false;
    }

    std::copy_n(data, kMacLength, frame.destination.begin());
    std::copy_n(data + kMacLength, kMacLength, frame.source.begin());
    frame.type = read_be16(data + 12);
    frame.payload_offset = kHeaderLength;
    frame.has_payload = caplen > kHeaderLength;
    frame.first_payload_byte =
        frame.has_payload ? data[kHeaderLength] : std::uint8_t{0};

    return true;
}

std::string mac_to_string(const MacAddress &mac)
{
    char text[18]; // "aa:bb:cc:dd:ee:ff" + '\0'
    std::snprintf(text, sizeof(text), "%02x:%02x:%02x:%02x:%02x:%02x",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(text);
}

const char *type_name(std::uint16_t type)
{
    // 0x0000-0x05DC（1500）在 Ethernet II 中表示 IEEE 802.3 的长度字段，
    // 而不是上层协议类型。这里单独处理，避免把长度误报成协议号。
    if (type <= 1500) {
        return "IEEE 802.3 length";
    }

    switch (type) {
    case 0x0800:
        return "IPv4";
    case 0x0806:
        return "ARP";
    case 0x8100:
        return "VLAN 802.1Q";
    case 0x86DD:
        return "IPv6";
    case 0x8847:
        return "MPLS unicast";
    case 0x8848:
        return "MPLS multicast";
    case 0x8863:
        return "PPPoE discovery";
    case 0x8864:
        return "PPPoE session";
    case 0x888E:
        return "EAPOL (802.1X)";
    case 0x88CC:
        return "LLDP";
    case 0x88F7:
        return "PTP (IEEE 1588)";
    default:
        return "Unknown";
    }
}

} // namespace ethernet
