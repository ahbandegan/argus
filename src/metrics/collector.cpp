#include "collector.hpp"
#include "../common/logger.hpp"

#include <condition_variable>

namespace argus {

namespace {

std::condition_variable cv_stop;
std::mutex cv_mutex;

} // anonymous namespace

MetricsCollector::MetricsCollector(const MonitoringConfig& config)
    : config_(config),
      start_time_(std::chrono::steady_clock::now()) {
    hardware_monitor_ = std::make_unique<HardwareMonitor>(config_.disk_mount_filter);
    network_monitor_ = std::make_unique<NetworkMonitor>(config_.connection_audit_history_size);
}

MetricsCollector::~MetricsCollector() {
    stop();
}

void MetricsCollector::start() {
    if (running_.exchange(true)) {
        return; // Already running
    }

    LOG_INFO("Starting background metrics collection engine (interval: ", config_.sample_interval_ms, "ms)...");

    // Perform an initial synchronous sample so valid data is immediately available
    hardware_monitor_->sample();
    network_monitor_->sample();

    auto hw = hardware_monitor_->get_snapshot();
    auto net = network_monitor_->get_network_snapshot();
    auto audit = network_monitor_->get_audit_snapshot();

    {
        std::unique_lock<std::shared_mutex> lock(rw_mutex_);
        cached_hardware_ = hw;
        cached_network_ = net;
        cached_audit_ = audit;

        cached_overview_ = OverviewSnapshot{
            .timestamp = hw.timestamp,
            .service_status = "healthy",
            .daemon_uptime_seconds = 0,
            .system_uptime_seconds = hw.system.uptime_seconds,
            .cpu_usage_percent = hw.cpu.overall_usage_percent,
            .memory_usage_percent = hw.memory.usage_percent,
            .memory_used_bytes = hw.memory.used_bytes,
            .memory_total_bytes = hw.memory.total_bytes,
            .network_rx_bytes_sec = net.totals.rx_bytes_per_sec,
            .network_tx_bytes_sec = net.totals.tx_bytes_per_sec,
            .active_connections_count = audit.active_connections_count,
            .load_1m = hw.system.load_1m,
            .load_5m = hw.system.load_5m,
            .load_15m = hw.system.load_15m
        };
    }

    worker_thread_ = std::thread(&MetricsCollector::collection_loop, this);
}

void MetricsCollector::stop() {
    if (!running_.exchange(false)) {
        return;
    }

    LOG_INFO("Stopping background metrics collection engine...");
    {
        std::lock_guard<std::mutex> lk(cv_mutex);
        cv_stop.notify_all();
    }

    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
    LOG_INFO("Metrics collection engine stopped.");
}

void MetricsCollector::collection_loop() {
    while (running_) {
        // Sleep until next tick or until woken by stop()
        {
            std::unique_lock<std::mutex> lk(cv_mutex);
            cv_stop.wait_for(lk, std::chrono::milliseconds(config_.sample_interval_ms), [this] {
                return !running_.load();
            });
        }

        if (!running_) break;

        // Sample monitors
        hardware_monitor_->sample();
        network_monitor_->sample();

        auto hw = hardware_monitor_->get_snapshot();
        auto net = network_monitor_->get_network_snapshot();
        auto audit = network_monitor_->get_audit_snapshot();

        uint64_t uptime_sec = get_daemon_uptime_seconds();

        OverviewSnapshot ov{
            .timestamp = hw.timestamp,
            .service_status = "healthy",
            .daemon_uptime_seconds = uptime_sec,
            .system_uptime_seconds = hw.system.uptime_seconds,
            .cpu_usage_percent = hw.cpu.overall_usage_percent,
            .memory_usage_percent = hw.memory.usage_percent,
            .memory_used_bytes = hw.memory.used_bytes,
            .memory_total_bytes = hw.memory.total_bytes,
            .network_rx_bytes_sec = net.totals.rx_bytes_per_sec,
            .network_tx_bytes_sec = net.totals.tx_bytes_per_sec,
            .active_connections_count = audit.active_connections_count,
            .load_1m = hw.system.load_1m,
            .load_5m = hw.system.load_5m,
            .load_15m = hw.system.load_15m
        };

        {
            std::unique_lock<std::shared_mutex> lock(rw_mutex_);
            cached_hardware_ = std::move(hw);
            cached_network_ = std::move(net);
            cached_audit_ = std::move(audit);
            cached_overview_ = std::move(ov);
        }
    }
}

uint64_t MetricsCollector::get_daemon_uptime_seconds() const {
    auto now = std::chrono::steady_clock::now();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(now - start_time_).count());
}

HardwareSnapshot MetricsCollector::get_hardware_metrics() const {
    std::shared_lock<std::shared_mutex> lock(rw_mutex_);
    return cached_hardware_;
}

NetworkSnapshot MetricsCollector::get_network_metrics() const {
    std::shared_lock<std::shared_mutex> lock(rw_mutex_);
    return cached_network_;
}

ConnectionAuditSnapshot MetricsCollector::get_connection_audit() const {
    std::shared_lock<std::shared_mutex> lock(rw_mutex_);
    return cached_audit_;
}

OverviewSnapshot MetricsCollector::get_overview() const {
    std::shared_lock<std::shared_mutex> lock(rw_mutex_);
    return cached_overview_;
}

nlohmann::json OverviewSnapshot::to_json() const {
    return {
        {"timestamp", timestamp},
        {"status", service_status},
        {"uptime", {
            {"daemon_seconds", daemon_uptime_seconds},
            {"system_seconds", system_uptime_seconds}
        }},
        {"cpu", {
            {"usage_percent", cpu_usage_percent}
        }},
        {"memory", {
            {"usage_percent", memory_usage_percent},
            {"used_bytes", memory_used_bytes},
            {"total_bytes", memory_total_bytes}
        }},
        {"network", {
            {"rx_bytes_per_sec", network_rx_bytes_sec},
            {"tx_bytes_per_sec", network_tx_bytes_sec}
        }},
        {"connections", {
            {"active_count", active_connections_count}
        }},
        {"load_average", {
            {"1m", load_1m},
            {"5m", load_5m},
            {"15m", load_15m}
        }}
    };
}

} // namespace argus
