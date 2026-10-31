#include "server.hpp"
#include "../common/logger.hpp"

#include <httplib.h>
#include <cmath>

namespace argus {

namespace {

constexpr std::string_view ARGUS_VERSION = "1.0.0";

} // anonymous namespace

ApiServer::ApiServer(const AppConfig& config, std::shared_ptr<MetricsCollector> collector)
    : config_(config),
      collector_(std::move(collector)) {

    authenticator_ = std::make_unique<TokenAuthenticator>(config_.security.api_token);

    if (config_.security.rate_limit.enabled) {
        rate_limiter_ = std::make_unique<RateLimiter>(
            config_.security.rate_limit.requests_per_minute,
            config_.security.rate_limit.burst_capacity
        );
    }

#if defined(CPPHTTPLIB_OPENSSL_SUPPORT)
    if (config_.security.tls.enabled) {
        LOG_INFO("Initializing REST API server with TLS/HTTPS support...");
        server_ = std::make_unique<httplib::SSLServer>(
            config_.security.tls.cert_file.c_str(),
            config_.security.tls.key_file.c_str()
        );
    } else {
        server_ = std::make_unique<httplib::Server>();
    }
#else
    if (config_.security.tls.enabled) {
        LOG_WARN("TLS requested but OpenSSL support was not compiled in. Falling back to HTTP.");
    }
    server_ = std::make_unique<httplib::Server>();
#endif

    setup_middleware();
    setup_routes();
}

ApiServer::~ApiServer() {
    stop();
}

void ApiServer::set_security_headers(httplib::Response& res) {
    res.set_header("X-Content-Type-Options", "nosniff");
    res.set_header("X-Frame-Options", "DENY");
    res.set_header("Content-Security-Policy", "default-src 'none'");
    res.set_header("Cache-Control", "no-store, no-cache, must-revalidate");
    res.set_header("Pragma", "no-cache");
    res.set_header("Server", "Argus-Daemon/1.0.0");
}

void ApiServer::send_json(httplib::Response& res, int status, const nlohmann::json& body) {
    set_security_headers(res);
    res.status = status;
    res.set_content(body.dump(2), "application/json; charset=utf-8");
}

void ApiServer::setup_middleware() {
    server_->set_pre_routing_handler([this](const httplib::Request& req, httplib::Response& res) {
        set_security_headers(res);

        // 1. Rate Limiting Check
        if (rate_limiter_) {
            double retry_after = 0.0;
            std::string client_ip = req.remote_addr;
            if (!rate_limiter_->allow(client_ip, retry_after)) {
                LOG_WARN("Rate limit triggered for client IP: ", client_ip, ". Retry-After: ", retry_after, "s");
                res.set_header("Retry-After", std::to_string(static_cast<int>(std::ceil(retry_after))));
                send_json(res, 429, {
                    {"error", "Too Many Requests"},
                    {"message", "Rate limit exceeded. Too many requests from this IP."},
                    {"retry_after_seconds", retry_after}
                });
                return httplib::Server::HandlerResponse::Handled;
            }
        }

        // 2. Authentication Check
        bool is_health_route = (req.path == "/api/v1/health" || req.path == "/health");
        bool allow_unauth_health = is_health_route && !config_.server.require_auth_for_health;

        if (!allow_unauth_health) {
            if (!authenticator_->authenticate(req)) {
                LOG_WARN("Unauthorized access attempt to '", req.path, "' from client IP: ", req.remote_addr);
                res.set_header("WWW-Authenticate", "Bearer realm=\"Argus Security Daemon\"");
                send_json(res, 401, {
                    {"error", "Unauthorized"},
                    {"message", "Missing, invalid, or expired Bearer token in Authorization header."}
                });
                return httplib::Server::HandlerResponse::Handled;
            }
        }

        return httplib::Server::HandlerResponse::Unhandled;
    });

    // 404 Not Found Handler
    server_->set_error_handler([](const httplib::Request& req, httplib::Response& res) {
        set_security_headers(res);
        if (res.status == 404) {
            res.set_content(nlohmann::json{
                {"error", "Not Found"},
                {"message", "The requested endpoint '" + req.path + "' does not exist."},
                {"available_endpoints", {
                    "/api/v1/health",
                    "/api/v1/metrics/hardware",
                    "/api/v1/metrics/network",
                    "/api/v1/audit/connections",
                    "/api/v1/overview"
                }}
            }.dump(2), "application/json; charset=utf-8");
        }
    });
}

void ApiServer::setup_routes() {
    // GET /api/v1/health
    server_->Get("/api/v1/health", [this](const httplib::Request& /*req*/, httplib::Response& res) {
        auto hw = collector_->get_hardware_metrics();
        nlohmann::json body = {
            {"status", "healthy"},
            {"service", "argus"},
            {"version", ARGUS_VERSION},
            {"daemon_uptime_seconds", collector_->get_daemon_uptime_seconds()},
            {"system_uptime_seconds", hw.system.uptime_seconds},
            {"timestamp", hw.timestamp}
        };
        send_json(res, 200, body);
    });

    // GET /api/v1/metrics/hardware
    server_->Get("/api/v1/metrics/hardware", [this](const httplib::Request& /*req*/, httplib::Response& res) {
        auto hw = collector_->get_hardware_metrics();
        send_json(res, 200, hw.to_json());
    });

    // GET /api/v1/metrics/network
    server_->Get("/api/v1/metrics/network", [this](const httplib::Request& /*req*/, httplib::Response& res) {
        auto net = collector_->get_network_metrics();
        send_json(res, 200, net.to_json());
    });

    // GET /api/v1/audit/connections
    server_->Get("/api/v1/audit/connections", [this](const httplib::Request& /*req*/, httplib::Response& res) {
        auto audit = collector_->get_connection_audit();
        send_json(res, 200, audit.to_json());
    });

    // GET /api/v1/overview
    server_->Get("/api/v1/overview", [this](const httplib::Request& /*req*/, httplib::Response& res) {
        auto ov = collector_->get_overview();
        send_json(res, 200, ov.to_json());
    });
}

bool ApiServer::bind() {
    if (is_bound_) return true;

    LOG_INFO("Binding REST API server to ", config_.server.bind_address, ":", config_.server.port, "...");
    if (!server_->bind_to_port(config_.server.bind_address.c_str(), config_.server.port)) {
        LOG_ERROR("Failed to bind REST API server to ", config_.server.bind_address, ":", config_.server.port);
        return false;
    }

    is_bound_ = true;
    LOG_INFO("REST API server successfully bound to ", config_.server.bind_address, ":", config_.server.port);
    return true;
}

bool ApiServer::listen() {
    if (!is_bound_) {
        if (!bind()) {
            return false;
        }
    }

    is_running_ = true;
    LOG_INFO("Argus REST API daemon listening on http", (config_.security.tls.enabled ? "s://" : "://"),
             config_.server.bind_address, ":", config_.server.port);

    bool result = server_->listen_after_bind();
    is_running_ = false;
    return result;
}

void ApiServer::stop() {
    if (is_running_.exchange(false)) {
        LOG_INFO("Stopping REST API server...");
        server_->stop();
        LOG_INFO("REST API server stopped.");
    }
}

bool ApiServer::is_running() const noexcept {
    return is_running_.load();
}

} // namespace argus
