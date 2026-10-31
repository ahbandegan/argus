#include "config.hpp"
#include "logger.hpp"
#include <fstream>
#include <cstdlib>

namespace argus {

AppConfig AppConfig::create_default() {
    AppConfig cfg;
    cfg.server.bind_address = "127.0.0.1";
    cfg.server.port = 9100;
    cfg.server.threads = 4;
    cfg.server.require_auth_for_health = false;

    cfg.security.api_token = "";
    cfg.security.rate_limit.enabled = true;
    cfg.security.rate_limit.requests_per_minute = 120;
    cfg.security.rate_limit.burst_capacity = 30;
    cfg.security.drop_privileges.enabled = true;
    cfg.security.drop_privileges.user = "argus_svc";
    cfg.security.drop_privileges.group = "argus_svc";
    cfg.security.tls.enabled = false;

    cfg.monitoring.sample_interval_ms = 1000;
    cfg.monitoring.connection_audit_history_size = 1000;

    cfg.logging.level = "INFO";
    cfg.logging.log_file = "/var/log/argus/argus.log";

    return cfg;
}

AppConfig AppConfig::load_from_file(const std::string& path) {
    AppConfig cfg = create_default();

    std::ifstream f(path);
    if (!f.is_open()) {
        LOG_WARN("Could not open config file: ", path, ". Using default configuration.");
        cfg.apply_environment_overrides();
        return cfg;
    }

    try {
        nlohmann::json j;
        f >> j;

        if (j.contains("server")) {
            const auto& s = j["server"];
            if (s.contains("bind_address")) cfg.server.bind_address = s["bind_address"].get<std::string>();
            if (s.contains("port")) cfg.server.port = s["port"].get<uint16_t>();
            if (s.contains("threads")) cfg.server.threads = s["threads"].get<size_t>();
            if (s.contains("require_auth_for_health")) cfg.server.require_auth_for_health = s["require_auth_for_health"].get<bool>();
        }

        if (j.contains("security")) {
            const auto& sec = j["security"];
            if (sec.contains("api_token")) cfg.security.api_token = sec["api_token"].get<std::string>();

            if (sec.contains("rate_limit")) {
                const auto& rl = sec["rate_limit"];
                if (rl.contains("enabled")) cfg.security.rate_limit.enabled = rl["enabled"].get<bool>();
                if (rl.contains("requests_per_minute")) cfg.security.rate_limit.requests_per_minute = rl["requests_per_minute"].get<size_t>();
                if (rl.contains("burst_capacity")) cfg.security.rate_limit.burst_capacity = rl["burst_capacity"].get<size_t>();
            }

            if (sec.contains("drop_privileges")) {
                const auto& dp = sec["drop_privileges"];
                if (dp.contains("enabled")) cfg.security.drop_privileges.enabled = dp["enabled"].get<bool>();
                if (dp.contains("user")) cfg.security.drop_privileges.user = dp["user"].get<std::string>();
                if (dp.contains("group")) cfg.security.drop_privileges.group = dp["group"].get<std::string>();
            }

            if (sec.contains("tls")) {
                const auto& tls = sec["tls"];
                if (tls.contains("enabled")) cfg.security.tls.enabled = tls["enabled"].get<bool>();
                if (tls.contains("cert_file")) cfg.security.tls.cert_file = tls["cert_file"].get<std::string>();
                if (tls.contains("key_file")) cfg.security.tls.key_file = tls["key_file"].get<std::string>();
            }
        }

        if (j.contains("monitoring")) {
            const auto& m = j["monitoring"];
            if (m.contains("sample_interval_ms")) cfg.monitoring.sample_interval_ms = m["sample_interval_ms"].get<uint32_t>();
            if (m.contains("connection_audit_history_size")) cfg.monitoring.connection_audit_history_size = m["connection_audit_history_size"].get<size_t>();
            if (m.contains("disk_mount_filter") && m["disk_mount_filter"].is_array()) {
                cfg.monitoring.disk_mount_filter = m["disk_mount_filter"].get<std::vector<std::string>>();
            }
        }

        if (j.contains("logging")) {
            const auto& l = j["logging"];
            if (l.contains("level")) cfg.logging.level = l["level"].get<std::string>();
            if (l.contains("log_file")) cfg.logging.log_file = l["log_file"].get<std::string>();
        }

        LOG_INFO("Successfully loaded configuration from: ", path);
    } catch (const std::exception& e) {
        LOG_ERROR("Error parsing config file ", path, ": ", e.what(), ". Using defaults with partial overrides.");
    }

    cfg.apply_environment_overrides();
    return cfg;
}

void AppConfig::apply_environment_overrides() {
    if (const char* token = std::getenv("ARGUS_API_TOKEN"); token && *token) {
        security.api_token = token;
        LOG_INFO("Security: API token overridden via ARGUS_API_TOKEN environment variable.");
    }

    if (const char* port_env = std::getenv("ARGUS_PORT"); port_env && *port_env) {
        server.port = static_cast<uint16_t>(std::atoi(port_env));
        LOG_INFO("Server: Port overridden via ARGUS_PORT: ", server.port);
    }

    if (const char* bind_env = std::getenv("ARGUS_BIND_ADDR"); bind_env && *bind_env) {
        server.bind_address = bind_env;
        LOG_INFO("Server: Bind address overridden via ARGUS_BIND_ADDR: ", server.bind_address);
    }
}

nlohmann::json AppConfig::to_json() const {
    return nlohmann::json{
        {"server", {
            {"bind_address", server.bind_address},
            {"port", server.port},
            {"threads", server.threads},
            {"require_auth_for_health", server.require_auth_for_health}
        }},
        {"security", {
            {"api_token", security.api_token.empty() ? "" : "[REDACTED]"},
            {"rate_limit", {
                {"enabled", security.rate_limit.enabled},
                {"requests_per_minute", security.rate_limit.requests_per_minute},
                {"burst_capacity", security.rate_limit.burst_capacity}
            }},
            {"drop_privileges", {
                {"enabled", security.drop_privileges.enabled},
                {"user", security.drop_privileges.user},
                {"group", security.drop_privileges.group}
            }},
            {"tls", {
                {"enabled", security.tls.enabled},
                {"cert_file", security.tls.cert_file},
                {"key_file", security.tls.key_file}
            }}
        }},
        {"monitoring", {
            {"sample_interval_ms", monitoring.sample_interval_ms},
            {"connection_audit_history_size", monitoring.connection_audit_history_size},
            {"disk_mount_filter", monitoring.disk_mount_filter}
        }},
        {"logging", {
            {"level", logging.level},
            {"log_file", logging.log_file}
        }}
    };
}

} // namespace argus
