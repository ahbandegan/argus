#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <nlohmann/json.hpp>

namespace argus {

struct CpuCoreSnapshot {
    uint32_t core_id{0};
    uint64_t user{0};
    uint64_t nice{0};
    uint64_t system{0};
    uint64_t idle{0};
    uint64_t iowait{0};
    uint64_t irq{0};
    uint64_t softirq{0};
    uint64_t steal{0};
    uint64_t guest{0};
    uint64_t guest_nice{0};

    [[nodiscard]] uint64_t total() const noexcept {
        return user + nice + system + idle + iowait + irq + softirq + steal;
    }

    [[nodiscard]] uint64_t idle_all() const noexcept {
        return idle + iowait;
    }
};

struct CpuCoreMetrics {
    uint32_t core_id{0};
    double usage_percent{0.0};
    double user_percent{0.0};
    double system_percent{0.0};
    double idle_percent{0.0};
    double iowait_percent{0.0};
    double steal_percent{0.0};
};

struct CpuMetrics {
    double overall_usage_percent{0.0};
    double user_percent{0.0};
    double system_percent{0.0};
    double idle_percent{0.0};
    double iowait_percent{0.0};
    double steal_percent{0.0};
    std::vector<CpuCoreMetrics> cores;
};

struct MemoryMetrics {
    uint64_t total_bytes{0};
    uint64_t free_bytes{0};
    uint64_t available_bytes{0};
    uint64_t used_bytes{0};
    uint64_t cached_bytes{0};
    uint64_t buffers_bytes{0};
    uint64_t shmem_bytes{0};
    uint64_t sreclaimable_bytes{0};
    double usage_percent{0.0};

    uint64_t swap_total_bytes{0};
    uint64_t swap_free_bytes{0};
    uint64_t swap_used_bytes{0};
    double swap_usage_percent{0.0};
};

struct FilesystemMetric {
    std::string mount_point;
    std::string device;
    std::string fs_type;
    uint64_t total_bytes{0};
    uint64_t used_bytes{0};
    uint64_t available_bytes{0};
    double usage_percent{0.0};
    uint64_t inodes_total{0};
    uint64_t inodes_used{0};
    uint64_t inodes_free{0};
    double inodes_usage_percent{0.0};
};

struct DiskIoSample {
    uint64_t reads_completed{0};
    uint64_t sectors_read{0};
    uint64_t time_reading_ms{0};
    uint64_t writes_completed{0};
    uint64_t sectors_written{0};
    uint64_t time_writing_ms{0};
    uint64_t io_in_progress{0};
    uint64_t io_time_ms{0};
};

struct DiskIoMetrics {
    std::string device;
    double read_bytes_per_sec{0.0};
    double write_bytes_per_sec{0.0};
    double read_iops{0.0};
    double write_iops{0.0};
    uint64_t io_in_progress{0};
    double io_utilization_percent{0.0};
};

struct SystemInfoMetrics {
    double uptime_seconds{0.0};
    double idle_seconds{0.0};
    double load_1m{0.0};
    double load_5m{0.0};
    double load_15m{0.0};
    uint64_t procs_running{0};
    uint64_t procs_blocked{0};
    uint64_t total_processes{0};
};

struct HardwareSnapshot {
    std::string timestamp;
    CpuMetrics cpu;
    MemoryMetrics memory;
    std::vector<FilesystemMetric> filesystems;
    std::vector<DiskIoMetrics> disk_io;
    SystemInfoMetrics system;

    [[nodiscard]] nlohmann::json to_json() const;
};

class HardwareMonitor {
public:
    explicit HardwareMonitor(std::vector<std::string> mount_filters = {});
    ~HardwareMonitor() = default;

    // Disallow copy
    HardwareMonitor(const HardwareMonitor&) = delete;
    HardwareMonitor& operator=(const HardwareMonitor&) = delete;

    void sample();
    [[nodiscard]] HardwareSnapshot get_snapshot() const;

private:
    void sample_cpu(double delta_sec, HardwareSnapshot& snap);
    void sample_memory(HardwareSnapshot& snap);
    void sample_disks(HardwareSnapshot& snap);
    void sample_disk_io(double delta_sec, HardwareSnapshot& snap);
    void sample_system(HardwareSnapshot& snap);

    mutable std::mutex mutex_;
    std::vector<std::string> mount_filters_;
    std::chrono::steady_clock::time_point last_sample_time_{};

    // Previous CPU state for deltas
    CpuCoreSnapshot prev_total_cpu_{};
    std::unordered_map<uint32_t, CpuCoreSnapshot> prev_cores_cpu_{};

    // Previous Disk I/O state for deltas
    std::unordered_map<std::string, DiskIoSample> prev_disk_io_{};

    HardwareSnapshot latest_snapshot_{};
    bool first_sample_{true};
};

} // namespace argus
