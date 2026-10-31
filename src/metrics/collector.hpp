#pragma once

#include "hardware.hpp"
#include "network.hpp"
#include "../common/config.hpp"

#include <thread>
#include <atomic>
#include <shared_mutex>
#include <memory>
#include <chrono>
#include <nlohmann/json.hpp>

namespace argus {

struct OverviewSnapshot {
    std::string timestamp;
    std::string service_status = "healthy";
    uint64_t daemon_uptime_seconds{0};
    double system_uptime_seconds{0.0};
    double cpu_usage_percent{0.0};
    double memory_usage_percent{0.0};
    uint64_t memory_used_bytes{0};
    uint64_t memory_total_bytes{0};
    double network_rx_bytes_sec{0.0};
    double network_tx_bytes_sec{0.0};
    size_t active_connections_count{0};
    double load_1m{0.0};
    double load_5m{0.0};
    double load_15m{0.0};

    [[nodiscard]] nlohmann::json to_json() const;
};

class MetricsCollector {
public:
    explicit MetricsCollector(const MonitoringConfig& config);
    ~MetricsCollector();

    MetricsCollector(const MetricsCollector&) = delete;
    MetricsCollector& operator=(const MetricsCollector&) = delete;

    void start();
    void stop();

    [[nodiscard]] HardwareSnapshot get_hardware_metrics() const;
    [[nodiscard]] NetworkSnapshot get_network_metrics() const;
    [[nodiscard]] ConnectionAuditSnapshot get_connection_audit() const;
    [[nodiscard]] OverviewSnapshot get_overview() const;
    [[nodiscard]] uint64_t get_daemon_uptime_seconds() const;

private:
    void collection_loop();

    MonitoringConfig config_;
    std::unique_ptr<HardwareMonitor> hardware_monitor_;
    std::unique_ptr<NetworkMonitor> network_monitor_;

    std::atomic<bool> running_{false};
    std::thread worker_thread_;

    mutable std::shared_mutex rw_mutex_;
    HardwareSnapshot cached_hardware_;
    NetworkSnapshot cached_network_;
    ConnectionAuditSnapshot cached_audit_;
    OverviewSnapshot cached_overview_;

    std::chrono::steady_clock::time_point start_time_;
};

} // namespace argus
