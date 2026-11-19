#include "ethernet.h"

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace {

int g_failures = 0;

void check(bool condition, const char *expression, int line)
{
    if (!condition) {
        std::cerr << "FAIL line " << line << ": " << expression << '\n';
        ++g_failures;
    }
}

#define CHECK(expression) check((expression), #expression, __LINE__)

using Bytes = std::vector<std::uint8_t>;

Bytes make_frame(const ethernet::MacAddress &destination,
                 const ethernet::MacAddress &source, std::uint16_t type,
                 const Bytes &payload = {})
{
    Bytes frame;
    frame.insert(frame.end(), destination.begin(), destination.end());
    frame.insert(frame.end(), source.begin(), source.end());
    frame.push_back(static_cast<std::uint8_t>(type >> 8));
    frame.push_back(static_cast<std::uint8_t>(type & 0xFF));
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

const ethernet::MacAddress kDestination = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
const ethernet::MacAddress kSource = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};

void test_ipv4_frame()
{
    const Bytes frame = make_frame(kDestination, kSource, 0x0800, {0x45, 0x00,
                                                                   0x00});
    ethernet::FrameView view;
    std::string error;
    CHECK(ethernet::parse(frame.data(), frame.size(), view, error));
    CHECK(error.empty());
    CHECK(ethernet::mac_to_string(view.source) == "66:77:88:99:aa:bb");
    CHECK(ethernet::mac_to_string(view.destination) == "00:11:22:33:44:55");
    CHECK(view.type == 0x0800);
    CHECK(view.has_payload);
    CHECK(view.first_payload_byte == 0x45);
    CHECK(view.payload_offset == 14);
    CHECK(std::string(ethernet::type_name(view.type)) == "IPv4");
}

void test_arp_first_byte_zero()
{
    // ARP 的硬件类型字段为 0x0001，因此首字节是 0x00。
    const Bytes frame =
        make_frame(kDestination, kSource, 0x0806, {0x00, 0x01, 0x08, 0x00});
    ethernet::FrameView view;
    std::string error;
    CHECK(ethernet::parse(frame.data(), frame.size(), view, error));
    CHECK(view.type == 0x0806);
    CHECK(view.has_payload);
    CHECK(view.first_payload_byte == 0x00);
    CHECK(std::string(ethernet::type_name(view.type)) == "ARP");
}

void test_vlan_outer_header()
{
    // 802.1Q：类型字段为 0x8100，其后的第一个字节是 TCI 的高字节。
    const Bytes frame =
        make_frame(kDestination, kSource, 0x8100, {0x00, 0x64, 0x08, 0x00});
    ethernet::FrameView view;
    std::string error;
    CHECK(ethernet::parse(frame.data(), frame.size(), view, error));
    CHECK(view.type == 0x8100);
    CHECK(view.first_payload_byte == 0x00);
    CHECK(std::string(ethernet::type_name(view.type)) == "VLAN 802.1Q");
}

void test_ipv6_frame()
{
    const Bytes frame =
        make_frame(kDestination, kSource, 0x86DD, {0x60, 0x00, 0x00, 0x00});
    ethernet::FrameView view;
    std::string error;
    CHECK(ethernet::parse(frame.data(), frame.size(), view, error));
    CHECK(view.type == 0x86DD);
    CHECK(view.first_payload_byte == 0x60);
    CHECK(std::string(ethernet::type_name(view.type)) == "IPv6");
}

void test_8023_length_field()
{
    const Bytes frame = make_frame(kDestination, kSource, 0x0036, {0xAA});
    ethernet::FrameView view;
    std::string error;
    CHECK(ethernet::parse(frame.data(), frame.size(), view, error));
    CHECK(view.type == 0x0036);
    CHECK(view.first_payload_byte == 0xAA);
    CHECK(std::string(ethernet::type_name(view.type)) == "IEEE 802.3 length");
}

void test_unknown_type()
{
    const Bytes frame = make_frame(kDestination, kSource, 0x1234, {0x00});
    ethernet::FrameView view;
    std::string error;
    CHECK(ethernet::parse(frame.data(), frame.size(), view, error));
    CHECK(view.type == 0x1234);
    CHECK(std::string(ethernet::type_name(view.type)) == "Unknown");
}

void test_header_only_frame()
{
    const Bytes frame = make_frame(kDestination, kSource, 0x0800);
    ethernet::FrameView view;
    std::string error;
    CHECK(ethernet::parse(frame.data(), frame.size(), view, error));
    CHECK(view.has_payload == false);
    CHECK(view.type == 0x0800);
}

void test_short_frame()
{
    Bytes frame = make_frame(kDestination, kSource, 0x0800, {0x45});
    frame.resize(13);

    ethernet::FrameView view;
    std::string error;
    CHECK(ethernet::parse(frame.data(), frame.size(), view, error) == false);
    CHECK(!error.empty());
    CHECK(error.find("too short") != std::string::npos);
}

void test_null_data()
{
    ethernet::FrameView view;
    std::string error;
    CHECK(ethernet::parse(nullptr, 64, view, error) == false);
    CHECK(!error.empty());
}

void test_mac_formatting()
{
    const ethernet::MacAddress mac = {0x00, 0x01, 0x0A, 0x0B, 0x0C, 0xFF};
    CHECK(ethernet::mac_to_string(mac) == "00:01:0a:0b:0c:ff");
}

} // namespace

int main()
{
    test_ipv4_frame();
    test_arp_first_byte_zero();
    test_vlan_outer_header();
    test_ipv6_frame();
    test_8023_length_field();
    test_unknown_type();
    test_header_only_frame();
    test_short_frame();
    test_null_data();
    test_mac_formatting();

    if (g_failures != 0) {
        std::cerr << g_failures << " test(s) failed.\n";
        return 1;
    }
    std::cout << "All Ethernet parser tests passed.\n";
    return 0;
}
