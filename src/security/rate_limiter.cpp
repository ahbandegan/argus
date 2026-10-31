#include "rate_limiter.hpp"
#include <algorithm>

namespace argus {

RateLimiter::RateLimiter(size_t requests_per_minute, size_t burst_capacity)
    : refill_rate_per_sec_(static_cast<double>(requests_per_minute) / 60.0),
      capacity_(static_cast<double>(burst_capacity)),
      last_cleanup_time_(std::chrono::steady_clock::now()) {}

bool RateLimiter::allow(const std::string& client_ip, double& out_retry_after_sec) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();

    cleanup_stale_entries(now);

    auto it = buckets_.find(client_ip);
    if (it == buckets_.end()) {
        // First request from this client: grant full capacity minus 1 token
        buckets_[client_ip] = Bucket{
            .tokens = capacity_ - 1.0,
            .last_refill = now
        };
        out_retry_after_sec = 0.0;
        return true;
    }

    Bucket& b = it->second;
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - b.last_refill).count();
    double elapsed_sec = static_cast<double>(elapsed_ms) / 1000.0;

    // Refill tokens
    b.tokens = std::min(capacity_, b.tokens + (elapsed_sec * refill_rate_per_sec_));
    b.last_refill = now;

    if (b.tokens >= 1.0) {
        b.tokens -= 1.0;
        out_retry_after_sec = 0.0;
        return true;
    }

    // Rate limit exceeded
    double missing_tokens = 1.0 - b.tokens;
    out_retry_after_sec = (refill_rate_per_sec_ > 0.0) ? (missing_tokens / refill_rate_per_sec_) : 1.0;
    return false;
}

void RateLimiter::cleanup_stale_entries(std::chrono::steady_clock::time_point now) {
    // Only run cleanup periodically (every 60 seconds) or when bucket count is large
    auto since_last_cleanup = std::chrono::duration_cast<std::chrono::seconds>(now - last_cleanup_time_).count();
    if (since_last_cleanup < 60 && buckets_.size() < 2048) {
        return;
    }

    last_cleanup_time_ = now;
    constexpr int64_t stale_timeout_sec = 600; // 10 minutes

    for (auto it = buckets_.begin(); it != buckets_.end(); ) {
        auto age_sec = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.last_refill).count();
        if (age_sec > stale_timeout_sec) {
            it = buckets_.erase(it);
        } else {
            ++it;
        }
    }
}

void RateLimiter::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    buckets_.clear();
}

} // namespace argus
