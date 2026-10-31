#include "hardware.hpp"
#include "../common/logger.hpp"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <filesystem>
#include <cmath>

#if defined(__linux__)
#include <sys/statvfs.h>
#include <unistd.h>
#include <cstdlib>
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

double calculate_percentage(uint64_t part, uint64_t total) noexcept {
    if (total == 0) return 0.0;
    double p = (static_cast<double>(part) / static_cast<double>(total)) * 100.0;
    return std::clamp(p, 0.0, 100.0);
}

} // anonymous namespace

HardwareMonitor::HardwareMonitor(std::vector<std::string> mount_filters)
    : mount_filters_(std::move(mount_filters)) {
    // Initial sample to prime previous metrics
    sample();
}

void HardwareMonitor::sample() {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::steady_clock::now();
    double delta_sec = 1.0;
    if (!first_sample_) {
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_sample_time_).count();
        delta_sec = (elapsed_ms > 0) ? (static_cast<double>(elapsed_ms) / 1000.0) : 1.0;
    }
    last_sample_time_ = now;

    HardwareSnapshot snap;
    snap.timestamp = get_current_iso_timestamp();

    sample_cpu(delta_sec, snap);
    sample_memory(snap);
    sample_disks(snap);
    sample_disk_io(delta_sec, snap);
    sample_system(snap);

    latest_snapshot_ = snap;
    first_sample_ = false;
}

HardwareSnapshot HardwareMonitor::get_snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return latest_snapshot_;
}

void HardwareMonitor::sample_cpu(double /*delta_sec*/, HardwareSnapshot& snap) {
    std::ifstream file("/proc/stat");
    if (!file.is_open()) {
        LOG_DEBUG("Cannot open /proc/stat");
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.rfind("cpu", 0) != 0) {
            // Reached non-cpu lines
            break;
        }

        std::istringstream ss(line);
        std::string cpu_label;
        ss >> cpu_label;

        CpuCoreSnapshot current{};
        ss >> current.user >> current.nice >> current.system >> current.idle
           >> current.iowait >> current.irq >> current.softirq >> current.steal
           >> current.guest >> current.guest_nice;

        if (cpu_label == "cpu") {
            // Overall CPU
            if (!first_sample_) {
                uint64_t prev_total = prev_total_cpu_.total();
                uint64_t curr_total = current.total();
                uint64_t delta_total = (curr_total >= prev_total) ? (curr_total - prev_total) : 0;

                uint64_t prev_idle = prev_total_cpu_.idle_all();
                uint64_t curr_idle = current.idle_all();
                uint64_t delta_idle = (curr_idle >= prev_idle) ? (curr_idle - prev_idle) : 0;

                uint64_t delta_user = (current.user >= prev_total_cpu_.user) ? (current.user - prev_total_cpu_.user) : 0;
                uint64_t delta_sys  = (current.system >= prev_total_cpu_.system) ? (current.system - prev_total_cpu_.system) : 0;
                uint64_t delta_iow  = (current.iowait >= prev_total_cpu_.iowait) ? (current.iowait - prev_total_cpu_.iowait) : 0;
                uint64_t delta_stl  = (current.steal >= prev_total_cpu_.steal) ? (current.steal - prev_total_cpu_.steal) : 0;

                if (delta_total > 0) {
                    uint64_t delta_active = (delta_total >= delta_idle) ? (delta_total - delta_idle) : 0;
                    snap.cpu.overall_usage_percent = calculate_percentage(delta_active, delta_total);
                    snap.cpu.idle_percent   = calculate_percentage(delta_idle, delta_total);
                    snap.cpu.user_percent   = calculate_percentage(delta_user, delta_total);
                    snap.cpu.system_percent = calculate_percentage(delta_sys, delta_total);
                    snap.cpu.iowait_percent = calculate_percentage(delta_iow, delta_total);
                    snap.cpu.steal_percent  = calculate_percentage(delta_stl, delta_total);
                }
            }
            prev_total_cpu_ = current;
        } else {
            // Per-core: cpu0, cpu1, ...
            try {
                uint32_t core_id = static_cast<uint32_t>(std::stoul(cpu_label.substr(3)));
                current.core_id = core_id;

                CpuCoreMetrics core_m{};
                core_m.core_id = core_id;

                if (!first_sample_ && prev_cores_cpu_.contains(core_id)) {
                    const auto& prev = prev_cores_cpu_[core_id];
                    uint64_t delta_total = (current.total() >= prev.total()) ? (current.total() - prev.total()) : 0;
                    uint64_t delta_idle  = (current.idle_all() >= prev.idle_all()) ? (current.idle_all() - prev.idle_all()) : 0;
                    uint64_t delta_user  = (current.user >= prev.user) ? (current.user - prev.user) : 0;
                    uint64_t delta_sys   = (current.system >= prev.system) ? (current.system - prev.system) : 0;
                    uint64_t delta_iow   = (current.iowait >= prev.iowait) ? (current.iowait - prev.iowait) : 0;
                    uint64_t delta_stl   = (current.steal >= prev.steal) ? (current.steal - prev.steal) : 0;

                    if (delta_total > 0) {
                        uint64_t delta_active = (delta_total >= delta_idle) ? (delta_total - delta_idle) : 0;
                        core_m.usage_percent  = calculate_percentage(delta_active, delta_total);
                        core_m.idle_percent   = calculate_percentage(delta_idle, delta_total);
                        core_m.user_percent   = calculate_percentage(delta_user, delta_total);
                        core_m.system_percent = calculate_percentage(delta_sys, delta_total);
                        core_m.iowait_percent = calculate_percentage(delta_iow, delta_total);
                        core_m.steal_percent  = calculate_percentage(delta_stl, delta_total);
                    }
                }
                snap.cpu.cores.push_back(core_m);
                prev_cores_cpu_[core_id] = current;
            } catch (...) {
                // Ignore unexpected parse error
            }
        }
    }
}

void HardwareMonitor::sample_memory(HardwareSnapshot& snap) {
    std::ifstream file("/proc/meminfo");
    if (!file.is_open()) {
        LOG_DEBUG("Cannot open /proc/meminfo");
        return;
    }

    std::string key;
    uint64_t value = 0;
    std::string unit;

    while (file >> key >> value) {
        // Read unit if present (e.g. "kB")
        std::getline(file, unit);

        // Standardize to bytes
        uint64_t bytes = value * 1024ULL;

        if (key == "MemTotal:") snap.memory.total_bytes = bytes;
        else if (key == "MemFree:") snap.memory.free_bytes = bytes;
        else if (key == "MemAvailable:") snap.memory.available_bytes = bytes;
        else if (key == "Buffers:") snap.memory.buffers_bytes = bytes;
        else if (key == "Cached:") snap.memory.cached_bytes = bytes;
        else if (key == "Shmem:") snap.memory.shmem_bytes = bytes;
        else if (key == "SReclaimable:") snap.memory.sreclaimable_bytes = bytes;
        else if (key == "SwapTotal:") snap.memory.swap_total_bytes = bytes;
        else if (key == "SwapFree:") snap.memory.swap_free_bytes = bytes;
    }

    // Modern Linux standard: MemUsed = MemTotal - MemAvailable
    if (snap.memory.available_bytes > 0 && snap.memory.total_bytes >= snap.memory.available_bytes) {
        snap.memory.used_bytes = snap.memory.total_bytes - snap.memory.available_bytes;
    } else if (snap.memory.total_bytes >= (snap.memory.free_bytes + snap.memory.buffers_bytes + snap.memory.cached_bytes)) {
        snap.memory.used_bytes = snap.memory.total_bytes - (snap.memory.free_bytes + snap.memory.buffers_bytes + snap.memory.cached_bytes);
    }

    snap.memory.usage_percent = calculate_percentage(snap.memory.used_bytes, snap.memory.total_bytes);

    if (snap.memory.swap_total_bytes >= snap.memory.swap_free_bytes) {
        snap.memory.swap_used_bytes = snap.memory.swap_total_bytes - snap.memory.swap_free_bytes;
    }
    snap.memory.swap_usage_percent = calculate_percentage(snap.memory.swap_used_bytes, snap.memory.swap_total_bytes);
}

void HardwareMonitor::sample_disks(HardwareSnapshot& snap) {
#if defined(__linux__)
    std::ifstream mounts("/proc/mounts");
    if (!mounts.is_open()) return;

    std::string line;
    std::vector<std::string> seen_mounts;

    while (std::getline(mounts, line)) {
        std::istringstream ss(line);
        std::string device, mount_point, fs_type;
        ss >> device >> mount_point >> fs_type;

        if (device.empty() || mount_point.empty()) continue;

        // Filter out pseudo/virtual filesystems
        if (device.rfind("/dev/", 0) != 0 && fs_type != "zfs" && fs_type != "btrfs" && fs_type != "overlay") {
            continue;
        }

        // Avoid duplicates or loop/squashfs mount spam
        if (device.rfind("/dev/loop", 0) == 0) continue;
        if (std::find(seen_mounts.begin(), seen_mounts.end(), mount_point) != seen_mounts.end()) continue;

        // If filter is provided, check if it matches
        if (!mount_filters_.empty()) {
            bool matched = false;
            for (const auto& filter : mount_filters_) {
                if (mount_point == filter) {
                    matched = true;
                    break;
                }
            }
            if (!matched) continue;
        }

        seen_mounts.push_back(mount_point);

        struct statvfs vfs{};
        if (statvfs(mount_point.c_str(), &vfs) == 0) {
            if (vfs.f_blocks == 0) continue;

            uint64_t block_size = vfs.f_frsize ? vfs.f_frsize : vfs.f_bsize;
            uint64_t total = vfs.f_blocks * block_size;
            uint64_t free_bytes = vfs.f_bfree * block_size;
            uint64_t avail_bytes = vfs.f_bavail * block_size;
            uint64_t used = (total >= free_bytes) ? (total - free_bytes) : 0;

            uint64_t inodes_total = vfs.f_files;
            uint64_t inodes_free  = vfs.f_ffree;
            uint64_t inodes_used  = (inodes_total >= inodes_free) ? (inodes_total - inodes_free) : 0;

            FilesystemMetric fsm;
            fsm.mount_point = mount_point;
            fsm.device = device;
            fsm.fs_type = fs_type;
            fsm.total_bytes = total;
            fsm.used_bytes = used;
            fsm.available_bytes = avail_bytes;
            fsm.usage_percent = calculate_percentage(used, total);

            fsm.inodes_total = inodes_total;
            fsm.inodes_used = inodes_used;
            fsm.inodes_free = inodes_free;
            fsm.inodes_usage_percent = calculate_percentage(inodes_used, inodes_total);

            snap.filesystems.push_back(fsm);
        }
    }
#else
    (void)snap;
#endif
}

void HardwareMonitor::sample_disk_io(double delta_sec, HardwareSnapshot& snap) {
    std::ifstream file("/proc/diskstats");
    if (!file.is_open()) return;

    std::string line;
    while (std::getline(file, line)) {
        std::istringstream ss(line);
        uint32_t major = 0, minor = 0;
        std::string dev_name;
        ss >> major >> minor >> dev_name;

        // Skip partitions (e.g. sda1, nvme0n1p1) and loop/ram/dm devices to focus on block devices
        // Physical disks usually: sda, sdb, vda, nvme0n1, xvda, etc.
        if (dev_name.rfind("loop", 0) == 0 || dev_name.rfind("ram", 0) == 0) {
            continue;
        }

        DiskIoSample curr{};
        uint64_t reads_merged = 0, writes_merged = 0, weighted_io_time = 0;
        ss >> curr.reads_completed >> reads_merged >> curr.sectors_read >> curr.time_reading_ms
           >> curr.writes_completed >> writes_merged >> curr.sectors_written >> curr.time_writing_ms
           >> curr.io_in_progress >> curr.io_time_ms >> weighted_io_time;

        if (ss.fail()) continue;

        if (!first_sample_ && prev_disk_io_.contains(dev_name)) {
            const auto& prev = prev_disk_io_[dev_name];

            uint64_t delta_reads = (curr.reads_completed >= prev.reads_completed) ? (curr.reads_completed - prev.reads_completed) : 0;
            uint64_t delta_writes = (curr.writes_completed >= prev.writes_completed) ? (curr.writes_completed - prev.writes_completed) : 0;
            uint64_t delta_r_sectors = (curr.sectors_read >= prev.sectors_read) ? (curr.sectors_read - prev.sectors_read) : 0;
            uint64_t delta_w_sectors = (curr.sectors_written >= prev.sectors_written) ? (curr.sectors_written - prev.sectors_written) : 0;
            uint64_t delta_io_time = (curr.io_time_ms >= prev.io_time_ms) ? (curr.io_time_ms - prev.io_time_ms) : 0;

            DiskIoMetrics io_m{};
            io_m.device = dev_name;
            // 1 sector = 512 bytes
            io_m.read_bytes_per_sec = (delta_sec > 0.0) ? (static_cast<double>(delta_r_sectors * 512ULL) / delta_sec) : 0.0;
            io_m.write_bytes_per_sec = (delta_sec > 0.0) ? (static_cast<double>(delta_w_sectors * 512ULL) / delta_sec) : 0.0;
            io_m.read_iops = (delta_sec > 0.0) ? (static_cast<double>(delta_reads) / delta_sec) : 0.0;
            io_m.write_iops = (delta_sec > 0.0) ? (static_cast<double>(delta_writes) / delta_sec) : 0.0;
            io_m.io_in_progress = curr.io_in_progress;
            // io_time_ms is in milliseconds
            io_m.io_utilization_percent = (delta_sec > 0.0) ? std::clamp((static_cast<double>(delta_io_time) / (delta_sec * 1000.0)) * 100.0, 0.0, 100.0) : 0.0;

            snap.disk_io.push_back(io_m);
        }

        prev_disk_io_[dev_name] = curr;
    }
}

void HardwareMonitor::sample_system(HardwareSnapshot& snap) {
    // 1. Uptime
    std::ifstream uptime_file("/proc/uptime");
    if (uptime_file.is_open()) {
        uptime_file >> snap.system.uptime_seconds >> snap.system.idle_seconds;
    }

    // 2. Load average
#if defined(__linux__)
    double loads[3] = {0.0, 0.0, 0.0};
    if (getloadavg(loads, 3) == 3) {
        snap.system.load_1m = loads[0];
        snap.system.load_5m = loads[1];
        snap.system.load_15m = loads[2];
    }
#endif

    // 3. Procs running and total from /proc/stat
    std::ifstream stat_file("/proc/stat");
    if (stat_file.is_open()) {
        std::string line;
        while (std::getline(stat_file, line)) {
            if (line.rfind("procs_running ", 0) == 0) {
                std::istringstream ss(line.substr(14));
                ss >> snap.system.procs_running;
            } else if (line.rfind("procs_blocked ", 0) == 0) {
                std::istringstream ss(line.substr(14));
                ss >> snap.system.procs_blocked;
            } else if (line.rfind("processes ", 0) == 0) {
                std::istringstream ss(line.substr(10));
                ss >> snap.system.total_processes;
            }
        }
    }
}

nlohmann::json HardwareSnapshot::to_json() const {
    nlohmann::json root;
    root["timestamp"] = timestamp;

    // CPU
    nlohmann::json cpu_json;
    cpu_json["overall_usage_percent"] = cpu.overall_usage_percent;
    cpu_json["user_percent"] = cpu.user_percent;
    cpu_json["system_percent"] = cpu.system_percent;
    cpu_json["idle_percent"] = cpu.idle_percent;
    cpu_json["iowait_percent"] = cpu.iowait_percent;
    cpu_json["steal_percent"] = cpu.steal_percent;

    nlohmann::json cores_array = nlohmann::json::array();
    for (const auto& c : cpu.cores) {
        cores_array.push_back({
            {"core_id", c.core_id},
            {"usage_percent", c.usage_percent},
            {"user_percent", c.user_percent},
            {"system_percent", c.system_percent},
            {"idle_percent", c.idle_percent},
            {"iowait_percent", c.iowait_percent},
            {"steal_percent", c.steal_percent}
        });
    }
    cpu_json["cores"] = cores_array;
    root["cpu"] = cpu_json;

    // Memory
    root["memory"] = {
        {"total_bytes", memory.total_bytes},
        {"used_bytes", memory.used_bytes},
        {"free_bytes", memory.free_bytes},
        {"available_bytes", memory.available_bytes},
        {"cached_bytes", memory.cached_bytes},
        {"buffers_bytes", memory.buffers_bytes},
        {"shmem_bytes", memory.shmem_bytes},
        {"sreclaimable_bytes", memory.sreclaimable_bytes},
        {"usage_percent", memory.usage_percent},
        {"swap", {
            {"total_bytes", memory.swap_total_bytes},
            {"used_bytes", memory.swap_used_bytes},
            {"free_bytes", memory.swap_free_bytes},
            {"usage_percent", memory.swap_usage_percent}
        }}
    };

    // Filesystems
    nlohmann::json fs_array = nlohmann::json::array();
    for (const auto& fs : filesystems) {
        fs_array.push_back({
            {"mount_point", fs.mount_point},
            {"device", fs.device},
            {"fs_type", fs.fs_type},
            {"total_bytes", fs.total_bytes},
            {"used_bytes", fs.used_bytes},
            {"available_bytes", fs.available_bytes},
            {"usage_percent", fs.usage_percent},
            {"inodes_total", fs.inodes_total},
            {"inodes_used", fs.inodes_used},
            {"inodes_free", fs.inodes_free},
            {"inodes_usage_percent", fs.inodes_usage_percent}
        });
    }
    root["disks"] = {
        {"filesystems", fs_array}
    };

    // Disk I/O
    nlohmann::json io_array = nlohmann::json::array();
    for (const auto& io : disk_io) {
        io_array.push_back({
            {"device", io.device},
            {"read_bytes_per_sec", io.read_bytes_per_sec},
            {"write_bytes_per_sec", io.write_bytes_per_sec},
            {"read_iops", io.read_iops},
            {"write_iops", io.write_iops},
            {"io_in_progress", io.io_in_progress},
            {"io_utilization_percent", io.io_utilization_percent}
        });
    }
    root["disks"]["io"] = io_array;

    // System
    root["system"] = {
        {"uptime_seconds", system.uptime_seconds},
        {"idle_seconds", system.idle_seconds},
        {"load_average", {
            {"1m", system.load_1m},
            {"5m", system.load_5m},
            {"15m", system.load_15m}
        }},
        {"procs_running", system.procs_running},
        {"procs_blocked", system.procs_blocked},
        {"total_processes", system.total_processes}
    };

    return root;
}

} // namespace argus
