#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <nlohmann/json.hpp>

namespace argus {

struct ServerConfig {
    std::string bind_address = "127.0.0.1";
    uint16_t port = 9100;
    size_t threads = 4;
    bool require_auth_for_health = false;
};

struct RateLimitConfig {
    bool enabled = true;
    size_t requests_per_minute = 120;
    size_t burst_capacity = 30;
};

struct PrivilegeConfig {
    bool enabled = true;
    std::string user = "argus_svc";
    std::string group = "argus_svc";
};

struct TlsConfig {
    bool enabled = false;
    std::string cert_file;
    std::string key_file;
};

struct SecurityConfig {
    std::string api_token;
    RateLimitConfig rate_limit;
    PrivilegeConfig drop_privileges;
    TlsConfig tls;
};

struct MonitoringConfig {
    uint32_t sample_interval_ms = 1000;
    size_t connection_audit_history_size = 1000;
    std::vector<std::string> disk_mount_filter;
};

struct LoggingConfig {
    std::string level = "INFO";
    std::string log_file;
};

struct AppConfig {
    ServerConfig server;
    SecurityConfig security;
    MonitoringConfig monitoring;
    LoggingConfig logging;

    static AppConfig load_from_file(const std::string& path);
    static AppConfig create_default();
    void apply_environment_overrides();
    nlohmann::json to_json() const;
};

} // namespace argus
