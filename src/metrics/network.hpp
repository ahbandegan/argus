#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <deque>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <nlohmann/json.hpp>

namespace argus {

struct NetworkInterfaceRates {
    double rx_bytes_per_sec{0.0};
    double tx_bytes_per_sec{0.0};
    double rx_packets_per_sec{0.0};
    double tx_packets_per_sec{0.0};
};

struct NetworkInterfaceMetrics {
    std::string name;
    uint64_t rx_bytes{0};
    uint64_t rx_packets{0};
    uint64_t rx_errors{0};
    uint64_t rx_drops{0};
    uint64_t tx_bytes{0};
    uint64_t tx_packets{0};
    uint64_t tx_errors{0};
    uint64_t tx_drops{0};
    NetworkInterfaceRates rates;
};

struct NetworkTotals {
    uint64_t rx_bytes_total{0};
    uint64_t tx_bytes_total{0};
    uint64_t rx_packets_total{0};
    uint64_t tx_packets_total{0};
    double rx_bytes_per_sec{0.0};
    double tx_bytes_per_sec{0.0};
    double rx_packets_per_sec{0.0};
    double tx_packets_per_sec{0.0};
};

struct NetworkSnapshot {
    std::string timestamp;
    std::vector<NetworkInterfaceMetrics> interfaces;
    NetworkTotals totals;

    [[nodiscard]] nlohmann::json to_json() const;
};

struct SocketConnection {
    std::string protocol;       // "TCP", "TCP6", "UDP", "UDP6"
    std::string local_ip;
    uint16_t local_port{0};
    std::string remote_ip;
    uint16_t remote_port{0};
    std::string state;          // "LISTEN", "ESTABLISHED", etc.
    uint32_t uid{0};
    uint64_t inode{0};
    int32_t pid{-1};
    std::string process_name;
};

struct ConnectionAuditEvent {
    std::string timestamp;
    std::string protocol;
    std::string client_ip;
    uint16_t client_port{0};
    uint16_t target_port{0};
    std::string state;
    int32_t pid{-1};
    std::string process_name;

    [[nodiscard]] nlohmann::json to_json() const;
};

struct ConnectionAuditSnapshot {
    std::string timestamp;
    size_t active_connections_count{0};
    std::vector<SocketConnection> active_connections;
    std::vector<ConnectionAuditEvent> audit_trail;

    [[nodiscard]] nlohmann::json to_json() const;
};

class NetworkMonitor {
public:
    explicit NetworkMonitor(size_t max_audit_history = 1000);
    ~NetworkMonitor() = default;

    NetworkMonitor(const NetworkMonitor&) = delete;
    NetworkMonitor& operator=(const NetworkMonitor&) = delete;

    void sample();
    [[nodiscard]] NetworkSnapshot get_network_snapshot() const;
    [[nodiscard]] ConnectionAuditSnapshot get_audit_snapshot() const;

private:
    void sample_interfaces(double delta_sec, NetworkSnapshot& snap);
    void sample_connections(ConnectionAuditSnapshot& snap);
    void refresh_socket_inode_map();

    static std::string decode_ipv4(const std::string& hex_ip);
    static std::string decode_ipv6(const std::string& hex_ip);
    static std::string tcp_state_to_string(uint8_t state) noexcept;
    static void parse_proc_net(const std::string& path, const std::string& proto,
                               const std::unordered_map<uint64_t, std::pair<int32_t, std::string>>& inode_map,
                               std::vector<SocketConnection>& out_conns);

    mutable std::mutex mutex_;
    size_t max_audit_history_;
    std::chrono::steady_clock::time_point last_sample_time_{};

    // Previous interface counters
    struct PrevInterfaceState {
        uint64_t rx_bytes{0};
        uint64_t tx_bytes{0};
        uint64_t rx_packets{0};
        uint64_t tx_packets{0};
    };
    std::unordered_map<std::string, PrevInterfaceState> prev_interfaces_{};

    // Inode to {PID, ProcessName} cache
    std::unordered_map<uint64_t, std::pair<int32_t, std::string>> socket_to_process_{};

    // Tracking seen active connections to record new arrivals in audit trail
    std::unordered_map<std::string, bool> active_connection_keys_{};
    std::deque<ConnectionAuditEvent> audit_history_{};

    NetworkSnapshot latest_network_snapshot_{};
    ConnectionAuditSnapshot latest_audit_snapshot_{};
    bool first_sample_{true};
};

} // namespace argus
