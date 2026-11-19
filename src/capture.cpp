#include "capture.h"

#include <sstream>
#include <utility>

namespace capture {

namespace {

std::string fallback(const char *text, const char *replacement)
{
    return (text != nullptr && text[0] != '\0') ? std::string(text)
                                                : std::string(replacement);
}

} // namespace

bool list_devices(std::vector<Device> &devices, std::string &error)
{
    devices.clear();
    error.clear();

    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_if_t *all = nullptr;
    if (pcap_findalldevs(&all, errbuf) == -1) {
        error = errbuf;
        return false;
    }

    for (pcap_if_t *item = all; item != nullptr; item = item->next) {
        Device device;
        device.name = fallback(item->name, "(unnamed)");
        device.description = fallback(item->description, "(no description)");
        device.loopback = (item->flags & PCAP_IF_LOOPBACK) != 0;

#ifdef PCAP_IF_UP
        device.up = (item->flags & PCAP_IF_UP) != 0;
#endif
#ifdef PCAP_IF_RUNNING
        device.running = (item->flags & PCAP_IF_RUNNING) != 0;
#endif

        devices.push_back(std::move(device));
    }

    pcap_freealldevs(all);
    return true;
}

Session::Session(pcap_t *handle) : handle_(handle) {}

Session::~Session()
{
    if (handle_ != nullptr) {
        pcap_close(handle_);
    }
}

std::unique_ptr<Session> Session::open_live(const std::string &device,
                                            int snaplen, bool promiscuous,
                                            int timeout_ms,
                                            std::string &error)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_t *handle = pcap_open_live(device.c_str(), snaplen,
                                    promiscuous ? 1 : 0, timeout_ms, errbuf);
    if (handle == nullptr) {
        error = errbuf[0] != '\0' ? errbuf : "pcap_open_live failed";
        return nullptr;
    }
    return std::unique_ptr<Session>(new Session(handle));
}

std::unique_ptr<Session> Session::open_offline(const std::string &path,
                                               std::string &error)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_t *handle = pcap_open_offline(path.c_str(), errbuf);
    if (handle == nullptr) {
        error = errbuf[0] != '\0' ? errbuf : "pcap_open_offline failed";
        return nullptr;
    }
    return std::unique_ptr<Session>(new Session(handle));
}

bool Session::set_filter(const std::string &bpf_expression, std::string &error)
{
    bpf_program program{};
    if (pcap_compile(handle_, &program, bpf_expression.c_str(), 1,
                     PCAP_NETMASK_UNKNOWN) == -1) {
        error = pcap_geterr(handle_);
        return false;
    }

    const int rc = pcap_setfilter(handle_, &program);
    pcap_freecode(&program);
    if (rc == -1) {
        error = pcap_geterr(handle_);
        return false;
    }
    return true;
}

int Session::datalink() const
{
    return pcap_datalink(handle_);
}

std::string Session::datalink_text() const
{
    const int link_type = pcap_datalink(handle_);
    const char *name = pcap_datalink_val_to_name(link_type);
    const char *description = pcap_datalink_val_to_description(link_type);

    std::ostringstream text;
    text << fallback(name, "UNKNOWN") << " ("
         << fallback(description, "unknown data link type") << ')';
    return text.str();
}

NextStatus Session::next(Packet &packet, std::string &error)
{
    pcap_pkthdr *header = nullptr;
    const u_char *data = nullptr;
    const int rc = pcap_next_ex(handle_, &header, &data);

    switch (rc) {
    case 1:
        if (header == nullptr || data == nullptr) {
            error = "pcap_next_ex returned a packet with no data";
            return NextStatus::Error;
        }
        packet.data = reinterpret_cast<const std::uint8_t *>(data);
        packet.captured_length = header->caplen;
        packet.original_length = header->len;
        packet.timestamp_sec = static_cast<std::int64_t>(header->ts.tv_sec);
        packet.timestamp_usec = static_cast<std::int64_t>(header->ts.tv_usec);
        return NextStatus::Packet;

    case 0:
        return NextStatus::Timeout;

    case -2:
        return NextStatus::EndOfFile;

    default:
        error = pcap_geterr(handle_);
        return NextStatus::Error;
    }
}

bool Session::read_stats(Stats &stats, std::string &error) const
{
    pcap_stat native{};
    if (pcap_stats(handle_, &native) == -1) {
        error = pcap_geterr(handle_);
        return false;
    }

    stats.received = native.ps_recv;
    stats.dropped = native.ps_drop;
    stats.interface_dropped = native.ps_ifdrop;
    return true;
}

} // namespace capture
