#include "network.hpp"
#include "../common/logger.hpp"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <filesystem>
#include <system_error>

#if defined(__linux__)
#include <arpa/inet.h>
#include <unistd.h>
#endif

namespace argus {

namespace {

std::string get_current_iso_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::tm tm_buf{};
#if defined(_WIN32)
    gmtime_s(&tm_buf, &in_time_t);
#else
    gmtime_r(&in_time_t, &tm_buf);
#endif

    std::ostringstream ss;
    ss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S")
       << '.' << std::setfill('0') << std::setw(3) << ms.count() << "Z";
    return ss.str();
}

bool is_numeric_string(std::string_view s) noexcept {
    return !s.empty() && std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return std::isdigit(c);
    });
}

} // anonymous namespace

NetworkMonitor::NetworkMonitor(size_t max_audit_history)
    : max_audit_history_(max_audit_history) {
    sample();
}

void NetworkMonitor::sample() {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::steady_clock::now();
    double delta_sec = 1.0;
    if (!first_sample_) {
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_sample_time_).count();
        delta_sec = (elapsed_ms > 0) ? (static_cast<double>(elapsed_ms) / 1000.0) : 1.0;
    }
    last_sample_time_ = now;

    // 1. Interfaces snapshot
    NetworkSnapshot net_snap;
    net_snap.timestamp = get_current_iso_timestamp();
    sample_interfaces(delta_sec, net_snap);
    latest_network_snapshot_ = net_snap;

    // 2. Refresh socket to process mapping and sample active connections
    refresh_socket_inode_map();

    ConnectionAuditSnapshot audit_snap;
    audit_snap.timestamp = net_snap.timestamp;
    sample_connections(audit_snap);
    latest_audit_snapshot_ = audit_snap;

    first_sample_ = false;
}

NetworkSnapshot NetworkMonitor::get_network_snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return latest_network_snapshot_;
}

ConnectionAuditSnapshot NetworkMonitor::get_audit_snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return latest_audit_snapshot_;
}

void NetworkMonitor::sample_interfaces(double delta_sec, NetworkSnapshot& snap) {
    std::ifstream file("/proc/net/dev");
    if (!file.is_open()) {
        LOG_DEBUG("Cannot open /proc/net/dev");
        return;
    }

    std::string line;
    // Skip headers (first 2 lines)
    std::getline(file, line);
    std::getline(file, line);

    while (std::getline(file, line)) {
        auto colon_pos = line.find(':');
        if (colon_pos == std::string::npos) continue;

        std::string iface_name = line.substr(0, colon_pos);
        // Trim leading and trailing whitespace
        iface_name.erase(0, iface_name.find_first_not_of(" \t"));
        iface_name.erase(iface_name.find_last_not_of(" \t") + 1);

        std::istringstream ss(line.substr(colon_pos + 1));
        uint64_t rx_bytes = 0, rx_packets = 0, rx_errs = 0, rx_drop = 0;
        uint64_t rx_fifo = 0, rx_frame = 0, rx_compressed = 0, rx_multicast = 0;
        uint64_t tx_bytes = 0, tx_packets = 0, tx_errs = 0, tx_drop = 0;
        uint64_t tx_fifo = 0, tx_colls = 0, tx_carrier = 0, tx_compressed = 0;

        ss >> rx_bytes >> rx_packets >> rx_errs >> rx_drop >> rx_fifo >> rx_frame >> rx_compressed >> rx_multicast
           >> tx_bytes >> tx_packets >> tx_errs >> tx_drop >> tx_fifo >> tx_colls >> tx_carrier >> tx_compressed;

        if (ss.fail()) continue;

        NetworkInterfaceMetrics m;
        m.name = iface_name;
        m.rx_bytes = rx_bytes;
        m.rx_packets = rx_packets;
        m.rx_errors = rx_errs;
        m.rx_drops = rx_drop;
        m.tx_bytes = tx_bytes;
        m.tx_packets = tx_packets;
        m.tx_errors = tx_errs;
        m.tx_drops = tx_drop;

        if (!first_sample_ && prev_interfaces_.contains(iface_name)) {
            const auto& prev = prev_interfaces_[iface_name];
            uint64_t delta_rx_b = (rx_bytes >= prev.rx_bytes) ? (rx_bytes - prev.rx_bytes) : 0;
            uint64_t delta_tx_b = (tx_bytes >= prev.tx_bytes) ? (tx_bytes - prev.tx_bytes) : 0;
            uint64_t delta_rx_p = (rx_packets >= prev.rx_packets) ? (rx_packets - prev.rx_packets) : 0;
            uint64_t delta_tx_p = (tx_packets >= prev.tx_packets) ? (tx_packets - prev.tx_packets) : 0;

            if (delta_sec > 0.0) {
                m.rates.rx_bytes_per_sec = static_cast<double>(delta_rx_b) / delta_sec;
                m.rates.tx_bytes_per_sec = static_cast<double>(delta_tx_b) / delta_sec;
                m.rates.rx_packets_per_sec = static_cast<double>(delta_rx_p) / delta_sec;
                m.rates.tx_packets_per_sec = static_cast<double>(delta_tx_p) / delta_sec;
            }
        }

        prev_interfaces_[iface_name] = PrevInterfaceState{
            .rx_bytes = rx_bytes,
            .tx_bytes = tx_bytes,
            .rx_packets = rx_packets,
            .tx_packets = tx_packets
        };

        // Aggregate totals (excluding loopback 'lo' from totals if multiple interfaces exist)
        if (iface_name != "lo" || snap.interfaces.empty()) {
            snap.totals.rx_bytes_total += m.rx_bytes;
            snap.totals.tx_bytes_total += m.tx_bytes;
            snap.totals.rx_packets_total += m.rx_packets;
            snap.totals.tx_packets_total += m.tx_packets;
            snap.totals.rx_bytes_per_sec += m.rates.rx_bytes_per_sec;
            snap.totals.tx_bytes_per_sec += m.rates.tx_bytes_per_sec;
            snap.totals.rx_packets_per_sec += m.rates.rx_packets_per_sec;
            snap.totals.tx_packets_per_sec += m.rates.tx_packets_per_sec;
        }

        snap.interfaces.push_back(std::move(m));
    }
}

void NetworkMonitor::refresh_socket_inode_map() {
    socket_to_process_.clear();

    std::error_code ec;
    std::filesystem::path proc_dir("/proc");
    if (!std::filesystem::exists(proc_dir, ec)) return;

    for (const auto& entry : std::filesystem::directory_iterator(proc_dir, ec)) {
        if (!entry.is_directory(ec)) continue;

        std::string filename = entry.path().filename().string();
        if (!is_numeric_string(filename)) continue;

        int32_t pid = 0;
        try {
            pid = std::stoi(filename);
        } catch (...) {
            continue;
        }

        // Read process comm (short name)
        std::string comm_path = entry.path() / "comm";
        std::string process_name;
        std::ifstream comm_file(comm_path);
        if (comm_file.is_open()) {
            std::getline(comm_file, process_name);
        }
        if (process_name.empty()) {
            process_name = "pid_" + filename;
        }

        // Iterate fd directory
        std::filesystem::path fd_dir = entry.path() / "fd";
        for (const auto& fd_entry : std::filesystem::directory_iterator(fd_dir, ec)) {
            if (ec) break; // Permission denied or process exited

            std::filesystem::path target = std::filesystem::read_symlink(fd_entry.path(), ec);
            if (ec) continue;

            std::string target_str = target.string();
            // Look for "socket:[<inode>]"
            if (target_str.rfind("socket:[", 0) == 0 && target_str.back() == ']') {
                std::string inode_str = target_str.substr(8, target_str.size() - 9);
                try {
                    uint64_t inode = std::stoull(inode_str);
                    socket_to_process_[inode] = {pid, process_name};
                } catch (...) {}
            }
        }
        ec.clear();
    }
}

std::string NetworkMonitor::decode_ipv4(const std::string& hex_ip) {
    if (hex_ip.size() != 8) return "0.0.0.0";
    try {
        uint32_t val = static_cast<uint32_t>(std::stoul(hex_ip, nullptr, 16));
        uint8_t b1 = val & 0xFF;
        uint8_t b2 = (val >> 8) & 0xFF;
        uint8_t b3 = (val >> 16) & 0xFF;
        uint8_t b4 = (val >> 24) & 0xFF;

        return std::to_string(b1) + "." + std::to_string(b2) + "." +
               std::to_string(b3) + "." + std::to_string(b4);
    } catch (...) {
        return "0.0.0.0";
    }
}

std::string NetworkMonitor::decode_ipv6(const std::string& hex_ip) {
    if (hex_ip.size() != 32) return "::";
#if defined(__linux__)
    struct in6_addr in6{};
    for (size_t w = 0; w < 4; ++w) {
        try {
            uint32_t word = static_cast<uint32_t>(std::stoul(hex_ip.substr(w * 8, 8), nullptr, 16));
            // Kernel prints words in host byte order
            in6.s6_addr[w * 4 + 0] = word & 0xFF;
            in6.s6_addr[w * 4 + 1] = (word >> 8) & 0xFF;
            in6.s6_addr[w * 4 + 2] = (word >> 16) & 0xFF;
            in6.s6_addr[w * 4 + 3] = (word >> 24) & 0xFF;
        } catch (...) {
            return "::";
        }
    }

    char buf[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, &in6, buf, sizeof(buf))) {
        return std::string(buf);
    }
#endif
    return "::";
}

std::string NetworkMonitor::tcp_state_to_string(uint8_t state) noexcept {
    switch (state) {
        case 0x01: return "ESTABLISHED";
        case 0x02: return "SYN_SENT";
        case 0x03: return "SYN_RECV";
        case 0x04: return "FIN_WAIT1";
        case 0x05: return "FIN_WAIT2";
        case 0x06: return "TIME_WAIT";
        case 0x07: return "CLOSE";
        case 0x08: return "CLOSE_WAIT";
        case 0x09: return "LAST_ACK";
        case 0x0A: return "LISTEN";
        case 0x0B: return "CLOSING";
        default:   return "UNKNOWN";
    }
}

void NetworkMonitor::parse_proc_net(const std::string& path, const std::string& proto,
                                   const std::unordered_map<uint64_t, std::pair<int32_t, std::string>>& inode_map,
                                   std::vector<SocketConnection>& out_conns) {
    std::ifstream file(path);
    if (!file.is_open()) return;

    std::string line;
    // Skip header line
    std::getline(file, line);

    while (std::getline(file, line)) {
        std::istringstream ss(line);
        std::string sl, local_addr_port, rem_addr_port, st_hex, tx_rx, tr_tm, retrnsmt;
        uint32_t uid = 0;
        uint64_t timeout = 0, inode = 0;

        ss >> sl >> local_addr_port >> rem_addr_port >> st_hex >> tx_rx >> tr_tm >> retrnsmt >> uid >> timeout >> inode;
        if (ss.fail()) continue;

        auto parse_addr_port = [&](const std::string& s, std::string& out_ip, uint16_t& out_port) {
            auto colon = s.find(':');
            if (colon == std::string::npos) return;
            std::string hex_ip = s.substr(0, colon);
            std::string hex_port = s.substr(colon + 1);

            if (proto == "TCP6" || proto == "UDP6") {
                out_ip = decode_ipv6(hex_ip);
            } else {
                out_ip = decode_ipv4(hex_ip);
            }

            try {
                out_port = static_cast<uint16_t>(std::stoul(hex_port, nullptr, 16));
            } catch (...) {
                out_port = 0;
            }
        };

        SocketConnection conn;
        conn.protocol = proto;
        parse_addr_port(local_addr_port, conn.local_ip, conn.local_port);
        parse_addr_port(rem_addr_port, conn.remote_ip, conn.remote_port);

        try {
            uint8_t state_code = static_cast<uint8_t>(std::stoul(st_hex, nullptr, 16));
            conn.state = (proto.rfind("UDP", 0) == 0) ? ((conn.remote_port == 0) ? "LISTEN" : "ESTABLISHED")
                                                      : tcp_state_to_string(state_code);
        } catch (...) {
            conn.state = "UNKNOWN";
        }

        conn.uid = uid;
        conn.inode = inode;

        auto it = inode_map.find(inode);
        if (it != inode_map.end()) {
            conn.pid = it->second.first;
            conn.process_name = it->second.second;
        } else {
            conn.pid = -1;
            conn.process_name = "unknown";
        }

        out_conns.push_back(std::move(conn));
    }
}

void NetworkMonitor::sample_connections(ConnectionAuditSnapshot& snap) {
    std::vector<SocketConnection> conns;
    conns.reserve(256);

    parse_proc_net("/proc/net/tcp", "TCP", socket_to_process_, conns);
    parse_proc_net("/proc/net/tcp6", "TCP6", socket_to_process_, conns);
    parse_proc_net("/proc/net/udp", "UDP", socket_to_process_, conns);
    parse_proc_net("/proc/net/udp6", "UDP6", socket_to_process_, conns);

    snap.active_connections_count = conns.size();

    // Check for new incoming connections to audit
    std::unordered_map<std::string, bool> current_keys;
    current_keys.reserve(conns.size());

    for (const auto& conn : conns) {
        // Construct unique connection identifier key
        std::string key = conn.protocol + ":" + conn.local_ip + ":" + std::to_string(conn.local_port) +
                          "->" + conn.remote_ip + ":" + std::to_string(conn.remote_port);
        current_keys[key] = true;

        // If it's an active connection (e.g. ESTABLISHED or SYN_RECV) and remote host is not unspecified (0.0.0.0 or ::)
        if ((conn.state == "ESTABLISHED" || conn.state == "SYN_RECV") &&
            conn.remote_ip != "0.0.0.0" && conn.remote_ip != "::" && conn.remote_port != 0) {
            if (!active_connection_keys_.contains(key)) {
                // New connection arrival detected! Add to audit history
                ConnectionAuditEvent event;
                event.timestamp = snap.timestamp;
                event.protocol = conn.protocol;
                event.client_ip = conn.remote_ip;
                event.client_port = conn.remote_port;
                event.target_port = conn.local_port;
                event.state = conn.state;
                event.pid = conn.pid;
                event.process_name = conn.process_name;

                audit_history_.push_front(event);
                if (audit_history_.size() > max_audit_history_) {
                    audit_history_.pop_back();
                }

                LOG_INFO("Audit [New Connection]: ", conn.protocol, " from ", conn.remote_ip, ":", conn.remote_port,
                         " -> Port ", conn.local_port, " (PID: ", conn.pid, " [", conn.process_name, "])");
            }
        }
    }

    active_connection_keys_ = std::move(current_keys);

    snap.active_connections = std::move(conns);
    snap.audit_trail.assign(audit_history_.begin(), audit_history_.end());
}

nlohmann::json NetworkSnapshot::to_json() const {
    nlohmann::json root;
    root["timestamp"] = timestamp;

    nlohmann::json ifaces_arr = nlohmann::json::array();
    for (const auto& iface : interfaces) {
        ifaces_arr.push_back({
            {"name", iface.name},
            {"rx_bytes", iface.rx_bytes},
            {"rx_packets", iface.rx_packets},
            {"rx_errors", iface.rx_errors},
            {"rx_drops", iface.rx_drops},
            {"tx_bytes", iface.tx_bytes},
            {"tx_packets", iface.tx_packets},
            {"tx_errors", iface.tx_errors},
            {"tx_drops", iface.tx_drops},
            {"rates", {
                {"rx_bytes_per_sec", iface.rates.rx_bytes_per_sec},
                {"tx_bytes_per_sec", iface.rates.tx_bytes_per_sec},
                {"rx_packets_per_sec", iface.rates.rx_packets_per_sec},
                {"tx_packets_per_sec", iface.rates.tx_packets_per_sec}
            }}
        });
    }
    root["interfaces"] = ifaces_arr;

    root["totals"] = {
        {"rx_bytes_total", totals.rx_bytes_total},
        {"tx_bytes_total", totals.tx_bytes_total},
        {"rx_packets_total", totals.rx_packets_total},
        {"tx_packets_total", totals.tx_packets_total},
        {"rx_bytes_per_sec", totals.rx_bytes_per_sec},
        {"tx_bytes_per_sec", totals.tx_bytes_per_sec},
        {"rx_packets_per_sec", totals.rx_packets_per_sec},
        {"tx_packets_per_sec", totals.tx_packets_per_sec}
    };

    return root;
}

nlohmann::json ConnectionAuditEvent::to_json() const {
    return {
        {"timestamp", timestamp},
        {"protocol", protocol},
        {"client_ip", client_ip},
        {"client_port", client_port},
        {"target_port", target_port},
        {"state", state},
        {"pid", pid},
        {"process_name", process_name}
    };
}

nlohmann::json ConnectionAuditSnapshot::to_json() const {
    nlohmann::json root;
    root["timestamp"] = timestamp;
    root["active_connections_count"] = active_connections_count;

    nlohmann::json conns_arr = nlohmann::json::array();
    for (const auto& c : active_connections) {
        conns_arr.push_back({
            {"protocol", c.protocol},
            {"local_ip", c.local_ip},
            {"local_port", c.local_port},
            {"remote_ip", c.remote_ip},
            {"remote_port", c.remote_port},
            {"state", c.state},
            {"uid", c.uid},
            {"inode", c.inode},
            {"pid", c.pid},
            {"process_name", c.process_name}
        });
    }
    root["active_connections"] = conns_arr;

    nlohmann::json audit_arr = nlohmann::json::array();
    for (const auto& a : audit_trail) {
        audit_arr.push_back(a.to_json());
    }
    root["audit_trail"] = audit_arr;

    return root;
}

} // namespace argus
