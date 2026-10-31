#pragma once

#include "../common/config.hpp"
#include "../metrics/collector.hpp"
#include "../security/auth.hpp"
#include "../security/rate_limiter.hpp"

#include <memory>
#include <string>
#include <atomic>

namespace httplib {
    class Server;
    struct Request;
    struct Response;
}

namespace argus {

class ApiServer {
public:
    ApiServer(const AppConfig& config, std::shared_ptr<MetricsCollector> collector);
    ~ApiServer();

    ApiServer(const ApiServer&) = delete;
    ApiServer& operator=(const ApiServer&) = delete;

    // Initializes routes and binds to port/address (supports binding before privilege drop)
    bool bind();

    // Starts the listening loop (blocking, call in thread or main)
    bool listen();

    // Gracefully terminates the HTTP server
    void stop();

    [[nodiscard]] bool is_running() const noexcept;

private:
    void setup_routes();
    void setup_middleware();

    static void set_security_headers(httplib::Response& res);
    static void send_json(httplib::Response& res, int status, const nlohmann::json& body);

    AppConfig config_;
    std::shared_ptr<MetricsCollector> collector_;
    std::unique_ptr<TokenAuthenticator> authenticator_;
    std::unique_ptr<RateLimiter> rate_limiter_;

    std::unique_ptr<httplib::Server> server_;
    std::atomic<bool> is_running_{false};
    bool is_bound_{false};
};

} // namespace argus
