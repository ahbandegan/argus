#pragma once

#include <string>
#include <unordered_map>
#include <mutex>
#include <chrono>

namespace argus {

class RateLimiter {
public:
    RateLimiter(size_t requests_per_minute, size_t burst_capacity);
    ~RateLimiter() = default;

    RateLimiter(const RateLimiter&) = delete;
    RateLimiter& operator=(const RateLimiter&) = delete;

    // Checks if the IP is allowed to proceed.
    // If allowed, consumes 1 token and returns true.
    // If rate-limited, returns false and populates out_retry_after_sec.
    bool allow(const std::string& client_ip, double& out_retry_after_sec);

    void reset();

private:
    struct Bucket {
        double tokens;
        std::chrono::steady_clock::time_point last_refill;
    };

    void cleanup_stale_entries(std::chrono::steady_clock::time_point now);

    double refill_rate_per_sec_;
    double capacity_;
    std::mutex mutex_;
    std::unordered_map<std::string, Bucket> buckets_;
    std::chrono::steady_clock::time_point last_cleanup_time_{};
};

} // namespace argus
