#include "capture.h"
#include "ethernet.h"

#include <algorithm>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <exception>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace {

volatile std::sig_atomic_t g_stop_requested = 0;

extern "C" void handle_sigint(int)
{
    g_stop_requested = 1;
}

struct Options {
    bool list_only = false;
    bool help = false;
    bool read_mode = false;
    std::string read_path;
    bool interface_given = false;
    std::string interface_arg;
    bool promiscuous = true;
    int snaplen = 65535;
    int timeout_ms = 500;
    std::uint64_t count = 0; // 0 表示不限制
    std::string filter;
};

void print_usage(const char *program)
{
    std::cout
        << "NPcap Ethernet frame sniffer (C++17)\n"
        << "\n"
        << "Usage:\n"
        << "  " << program << " [options]\n"
        << "\n"
        << "Options:\n"
        << "  -l, --list               List capture devices and exit\n"
        << "  -i, --interface <sel>    Device index (1-based) or pcap name;\n"
        << "                           ask interactively when omitted\n"
        << "  -c, --count <n>          Stop after n frames (0 = unlimited)\n"
        << "  -f, --filter <expr>      BPF filter, e.g. \"arp or ip\"\n"
        << "  -r, --read <file>        Read frames from a pcap/pcapng file\n"
        << "                           (offline verification mode)\n"
        << "  -s, --snaplen <n>        Snapshot length (default 65535)\n"
        << "  -p, --no-promisc         Disable promiscuous mode\n"
        << "  -t, --timeout-ms <n>     Read timeout in milliseconds (default 500)\n"
        << "  -h, --help               Show this help\n"
        << "\n"
        << "Examples:\n"
        << "  " << program << " --list\n"
        << "  " << program << " -i 1 -c 20 -f \"arp or ip\"\n"
        << "  " << program << " -r capture.pcap            # replay a file\n";
}

bool parse_u64(const std::string &text, std::uint64_t &value)
{
    if (text.empty() || text.front() == '-') {
        return false;
    }
    try {
        std::size_t used = 0;
        const unsigned long long parsed = std::stoull(text, &used, 10);
        if (used != text.size()) {
            return false;
        }
        value = static_cast<std::uint64_t>(parsed);
        return true;
    } catch (const std::exception &) {
        return false;
    }
}

bool parse_int(const std::string &text, int &value, int minimum, int maximum)
{
    try {
        std::size_t used = 0;
        const long parsed = std::stol(text, &used, 10);
        if (used != text.size() || parsed < minimum || parsed > maximum) {
            return false;
        }
        value = static_cast<int>(parsed);
        return true;
    } catch (const std::exception &) {
        return false;
    }
}

bool parse_options(int argc, char **argv, Options &options, std::string &error)
{
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto need_value = [&](const char *name) -> const char * {
            if (i + 1 >= argc) {
                error = std::string("missing value for ") + name;
                return nullptr;
            }
            return argv[++i];
        };

        if (arg == "-h" || arg == "--help") {
            options.help = true;
        } else if (arg == "-l" || arg == "--list") {
            options.list_only = true;
        } else if (arg == "-i" || arg == "--interface") {
            const char *value = need_value("--interface");
            if (value == nullptr) {
                return false;
            }
            options.interface_given = true;
            options.interface_arg = value;
        } else if (arg == "-c" || arg == "--count") {
            const char *value = need_value("--count");
            if (value == nullptr) {
                return false;
            }
            if (!parse_u64(value, options.count)) {
                error = "invalid --count value (expected a non-negative integer)";
                return false;
            }
        } else if (arg == "-f" || arg == "--filter") {
            const char *value = need_value("--filter");
            if (value == nullptr) {
                return false;
            }
            options.filter = value;
        } else if (arg == "-r" || arg == "--read") {
            const char *value = need_value("--read");
            if (value == nullptr) {
                return false;
            }
            options.read_mode = true;
            options.read_path = value;
        } else if (arg == "-s" || arg == "--snaplen") {
            const char *value = need_value("--snaplen");
            if (value == nullptr) {
                return false;
            }
            if (!parse_int(value, options.snaplen, 1, 262144)) {
                error = "invalid --snaplen value (expected 1..262144)";
                return false;
            }
        } else if (arg == "-p" || arg == "--no-promisc") {
            options.promiscuous = false;
        } else if (arg == "-t" || arg == "--timeout-ms") {
            const char *value = need_value("--timeout-ms");
            if (value == nullptr) {
                return false;
            }
            if (!parse_int(value, options.timeout_ms, 1, 60000)) {
                error = "invalid --timeout-ms value (expected 1..60000)";
                return false;
            }
        } else {
            error = "unknown option: " + arg;
            return false;
        }
    }

    if (options.read_mode && options.interface_given) {
        error = "--read cannot be combined with --interface";
        return false;
    }
    return true;
}

void print_devices(const std::vector<capture::Device> &devices)
{
    std::cout << "Capture devices (" << devices.size() << "):\n";
    for (std::size_t i = 0; i < devices.size(); ++i) {
        const capture::Device &device = devices[i];
        std::cout << '[' << std::setw(2) << std::right << (i + 1) << "] "
                  << device.name << '\n'
                  << "     " << device.description;

        std::vector<std::string> flags;
        if (device.loopback) {
            flags.emplace_back("loopback");
        }
        if (device.up) {
            flags.emplace_back("up");
        }
        if (device.running) {
            flags.emplace_back("running");
        }
        if (!flags.empty()) {
            std::cout << "  [";
            for (std::size_t j = 0; j < flags.size(); ++j) {
                if (j != 0) {
                    std::cout << ", ";
                }
                std::cout << flags[j];
            }
            std::cout << ']';
        }
        std::cout << '\n';
    }
}

std::string trim(const std::string &text)
{
    const auto first = text.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return {};
    }
    const auto last = text.find_last_not_of(" \t\r\n");
    return text.substr(first, last - first + 1);
}

/* 返回设备下标；用户输入 q 时 cancelled=true。 */
int choose_device_interactively(const std::vector<capture::Device> &devices,
                                bool &cancelled, std::string &error)
{
    cancelled = false;
    while (true) {
        std::cout << "Select a device [1-" << devices.size()
                  << "] (q to quit): " << std::flush;

        std::string line;
        if (!std::getline(std::cin, line)) {
            error = "no input available";
            return -1;
        }
        line = trim(line);
        if (line == "q" || line == "Q") {
            cancelled = true;
            return -1;
        }
        if (line.empty()) {
            line = "1";
        }

        int index = 0;
        if (parse_int(line, index, 1, static_cast<int>(devices.size()))) {
            return index - 1;
        }
        std::cout << "Invalid selection: " << line << '\n';
    }
}

bool select_device(const std::vector<capture::Device> &devices,
                   const Options &options, std::size_t &selected,
                   bool &cancelled, std::string &error)
{
    if (!options.interface_given) {
        const int index = choose_device_interactively(devices, cancelled, error);
        if (index < 0) {
            return false;
        }
        selected = static_cast<std::size_t>(index);
        return true;
    }

    const std::string &arg = options.interface_arg;
    int index = 0;
    if (parse_int(arg, index, 1, static_cast<int>(devices.size()))) {
        selected = static_cast<std::size_t>(index - 1);
        return true;
    }

    for (std::size_t i = 0; i < devices.size(); ++i) {
        if (devices[i].name == arg || devices[i].description == arg) {
            selected = i;
            return true;
        }
    }

    error = "device not found: " + arg;
    return false;
}

std::string format_time(std::int64_t seconds, std::int64_t microseconds)
{
    const std::time_t raw = static_cast<std::time_t>(seconds);
    std::tm local{};
#ifdef _WIN32
    localtime_s(&local, &raw);
#else
    localtime_r(&raw, &local);
#endif

    char hms[16] = {};
    if (std::strftime(hms, sizeof(hms), "%H:%M:%S", &local) == 0) {
        std::snprintf(hms, sizeof(hms), "??:??:??");
    }

    char result[24] = {};
    std::snprintf(result, sizeof(result), "%s.%03d", hms,
                  static_cast<int>(microseconds / 1000));
    return std::string(result);
}

void print_table_header()
{
    std::cout
        << "\n"
        << " No.  Time          Source MAC         Destination MAC    "
           "EtherType  Protocol            First byte\n"
        << "----  ------------  -----------------  -----------------  "
           "---------  ------------------  ----------\n";
}

void print_frame_row(std::uint64_t number,
                     const ethernet::FrameView &frame,
                     const capture::Packet &packet)
{
    const std::string time =
        format_time(packet.timestamp_sec, packet.timestamp_usec);
    const std::string source = ethernet::mac_to_string(frame.source);
    const std::string destination =
        ethernet::mac_to_string(frame.destination);

    std::printf("%4llu  %-12s  %-17s  %-17s  0x%04X     %-18s  ",
                static_cast<unsigned long long>(number), time.c_str(),
                source.c_str(), destination.c_str(), frame.type,
                ethernet::type_name(frame.type));

    if (frame.has_payload) {
        std::printf("0x%02X (%3u)\n", frame.first_payload_byte,
                    static_cast<unsigned>(frame.first_payload_byte));
    } else {
        std::printf("N/A (no payload)\n");
    }
}

void print_malformed_row(std::uint64_t number, const capture::Packet &packet,
                         const std::string &reason)
{
    const std::string time =
        format_time(packet.timestamp_sec, packet.timestamp_usec);
    std::printf("%4llu  %-12s  <malformed: %s>\n",
                static_cast<unsigned long long>(number), time.c_str(),
                reason.c_str());
}

void print_summary(std::uint64_t frames_read, std::uint64_t frames_shown,
                   std::uint64_t malformed, bool read_mode,
                   const capture::Session &session)
{
    std::cout << "\n--- Capture summary ---\n"
              << "Frames read       : " << frames_read << '\n'
              << "Frames displayed  : " << frames_shown << '\n'
              << "Malformed frames  : " << malformed << '\n';

    if (read_mode) {
        std::cout << "Mode              : offline file\n";
        return;
    }

    capture::Stats stats;
    std::string error;
    if (session.read_stats(stats, error)) {
        std::cout << "Packets received  : " << stats.received << '\n'
                  << "Packets dropped   : " << stats.dropped << '\n'
                  << "Interface dropped : " << stats.interface_dropped << '\n';
    } else {
        std::cout << "Statistics        : unavailable (" << error << ")\n";
    }
}

std::unique_ptr<capture::Session> open_capture(const Options &options,
                                               bool &cancelled,
                                               std::string &error)
{
    cancelled = false;
    if (options.read_mode) {
        return capture::Session::open_offline(options.read_path, error);
    }

    std::vector<capture::Device> devices;
    if (!capture::list_devices(devices, error)) {
        return nullptr;
    }
    if (devices.empty()) {
        error = "no capture devices found";
        return nullptr;
    }

    if (!options.interface_given) {
        print_devices(devices);
    }

    std::size_t selected = 0;
    if (!select_device(devices, options, selected, cancelled, error)) {
        return nullptr;
    }

    const capture::Device &device = devices[selected];
    std::cout << "\nDevice         : " << device.name << '\n'
              << "Description    : " << device.description << '\n';

    return capture::Session::open_live(device.name, options.snaplen,
                                       options.promiscuous, options.timeout_ms,
                                       error);
}

int run_capture(const Options &options)
{
    std::string error;
    bool cancelled = false;
    std::unique_ptr<capture::Session> session =
        open_capture(options, cancelled, error);
    if (!session) {
        if (cancelled) {
            std::cout << "Cancelled.\n";
            return 0;
        }
        if (!error.empty()) {
            std::cerr << "Error: " << error << '\n';
            if (!options.read_mode && error == "no capture devices found") {
                std::cerr
                    << "Hints:\n"
                    << "  - Install Npcap from https://npcap.com/\n"
                    << "  - Run this program as Administrator\n"
                    << "  - Check the npcap service: sc query npcap\n";
            }
        }
        return 1;
    }

    if (session->datalink() != DLT_EN10MB) {
        std::cerr << "Error: selected capture source uses "
                  << session->datalink_text() << ".\n"
                  << "This program parses Ethernet II headers and requires "
                     "DLT_EN10MB.\n"
                  << "Choose a physical Ethernet/Wi-Fi adapter, not the "
                     "NPF_Loopback adapter.\n";
        return 2;
    }

    if (!options.filter.empty() &&
        !session->set_filter(options.filter, error)) {
        std::cerr << "Error: invalid BPF filter: " << error << '\n';
        return 1;
    }

    std::cout << "Data link type : " << session->datalink_text() << '\n'
              << "Promiscuous    : " << (options.promiscuous ? "yes" : "no")
              << '\n'
              << "BPF filter     : "
              << (options.filter.empty() ? "(none)" : options.filter) << '\n'
              << "Frame limit    : "
              << (options.count == 0 ? "unlimited (Ctrl+C to stop)"
                                     : std::to_string(options.count))
              << "\n\n"
              << "Capturing...\n";

    print_table_header();

    std::uint64_t frames_read = 0;
    std::uint64_t frames_shown = 0;
    std::uint64_t malformed = 0;

    while (!g_stop_requested &&
           (options.count == 0 || frames_read < options.count)) {
        capture::Packet packet;
        const capture::NextStatus status = session->next(packet, error);

        if (status == capture::NextStatus::Timeout) {
            continue;
        }
        if (status == capture::NextStatus::EndOfFile) {
            std::cout << "End of capture file reached.\n";
            break;
        }
        if (status == capture::NextStatus::Error) {
            if (!g_stop_requested) {
                std::cerr << "\nCapture error: " << error << '\n';
            }
            break;
        }

        ++frames_read;

        ethernet::FrameView frame;
        if (!ethernet::parse(packet.data, packet.captured_length, frame,
                             error)) {
            ++malformed;
            print_malformed_row(frames_read, packet, error);
        } else {
            print_frame_row(frames_read, frame, packet);
            ++frames_shown;
        }
        std::fflush(stdout);
    }

    if (g_stop_requested) {
        std::cout << "\nInterrupted by user.\n";
    }

    print_summary(frames_read, frames_shown, malformed, options.read_mode,
                  *session);
    return 0;
}

} // namespace

int main(int argc, char **argv)
{
    Options options;
    std::string error;
    if (!parse_options(argc, argv, options, error)) {
        std::cerr << "Error: " << error << "\n\n";
        print_usage(argv[0]);
        return 1;
    }
    if (options.help) {
        print_usage(argv[0]);
        return 0;
    }

    if (options.list_only) {
        std::vector<capture::Device> devices;
        if (!capture::list_devices(devices, error)) {
            std::cerr << "Error: " << error << '\n';
            return 1;
        }
        print_devices(devices);
        if (devices.empty()) {
            std::cerr << "No capture devices found. Install Npcap and run as "
                         "Administrator.\n";
            return 1;
        }
        return 0;
    }

    std::signal(SIGINT, handle_sigint);

    try {
        return run_capture(options);
    } catch (const std::exception &exception) {
        std::cerr << "Fatal error: " << exception.what() << '\n';
        return 1;
    }
}
