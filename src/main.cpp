#include "common/config.hpp"
#include "common/logger.hpp"
#include "metrics/collector.hpp"
#include "security/privilege.hpp"
#include "api/server.hpp"

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <csignal>
#include <atomic>
#include <filesystem>

namespace {

constexpr std::string_view ARGUS_VERSION = "1.0.0";

std::atomic<argus::ApiServer*> g_server_ptr{nullptr};
std::atomic<bool> g_shutdown_requested{false};

void handle_signal(int signum) {
    g_shutdown_requested.store(true);
    LOG_INFO("Received termination signal (", signum, "). Initiating graceful shutdown...");
    if (auto* srv = g_server_ptr.load()) {
        srv->stop();
    }
}

void print_banner() {
    std::cout << R"(
    █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
   ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
   ███████║██████╔╝██║  ███╗██║   ██║███████╗
   ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
   ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
      Linux Kernel Security & System Monitor v)" << ARGUS_VERSION << R"(
    )" << std::endl;
}

void print_help(const char* prog_name) {
    print_banner();
    std::cout << "Usage: " << prog_name << " [options]\n\n"
              << "Options:\n"
              << "  -c, --config <file>   Path to JSON configuration file (default: /etc/argus/config.json or ./config.json)\n"
              << "  -p, --port <port>     Override HTTP API listening port\n"
              << "  -b, --bind <ip>       Override HTTP API bind address (default: 127.0.0.1)\n"
              << "  -t, --token <token>   Override API Bearer authentication token\n"
              << "  -v, --version         Display version and build information\n"
              << "  -h, --help            Display this help message\n\n"
              << "Environment Variables:\n"
              << "  ARGUS_API_TOKEN       Bearer token for authentication\n"
              << "  ARGUS_PORT            Port number override\n"
              << "  ARGUS_BIND_ADDR       Bind IP address override\n"
              << std::endl;
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    std::string config_path;
    std::optional<uint16_t> port_override;
    std::optional<std::string> bind_override;
    std::optional<std::string> token_override;

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_help(argv[0]);
            return 0;
        } else if (arg == "-v" || arg == "--version") {
            std::cout << "Argus System Monitoring Daemon v" << ARGUS_VERSION << " (Modern C++20 Linux)" << std::endl;
            return 0;
        } else if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            config_path = argv[++i];
        } else if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            port_override = static_cast<uint16_t>(std::stoul(argv[++i]));
        } else if ((arg == "-b" || arg == "--bind") && i + 1 < argc) {
            bind_override = argv[++i];
        } else if ((arg == "-t" || arg == "--token") && i + 1 < argc) {
            token_override = argv[++i];
        } else {
            std::cerr << "Unknown argument: " << arg << "\nRun with -h for help." << std::endl;
            return 1;
        }
    }

    print_banner();

    // Determine config file path
    if (config_path.empty()) {
        if (std::filesystem::exists("/etc/argus/config.json")) {
            config_path = "/etc/argus/config.json";
        } else if (std::filesystem::exists("config.json")) {
            config_path = "config.json";
        } else {
            config_path = "/etc/argus/config.json"; // default path
        }
    }

    // Load configuration
    argus::AppConfig config = argus::AppConfig::load_from_file(config_path);

    // Apply CLI overrides
    if (port_override) config.server.port = *port_override;
    if (bind_override) config.server.bind_address = *bind_override;
    if (token_override) config.security.api_token = *token_override;

    // Configure logger
    argus::Logger::instance().set_level_from_string(config.logging.level);
    if (!config.logging.log_file.empty()) {
        argus::Logger::instance().set_log_file(config.logging.log_file);
    }

    LOG_INFO("Initializing Argus Daemon v", ARGUS_VERSION, " [C++20 Zero-Trust Linux Monitor]");
    LOG_INFO("Process ID: ",
#if defined(__linux__)
             getpid()
#else
             0
#endif
             , ", Running as: ", argus::PrivilegeManager::get_current_user_info());

    // Security warning checks
    if (config.security.api_token.empty()) {
        LOG_WARN("======================================================================");
        LOG_WARN("CRITICAL SECURITY NOTICE: No API authentication token configured!");
        LOG_WARN("Set a token via config.json or ARGUS_API_TOKEN environment variable.");
        LOG_WARN("Requests to protected endpoints will be rejected.");
        LOG_WARN("======================================================================");
    }

    if (config.server.bind_address == "0.0.0.0") {
        LOG_WARN("NETWORK NOTICE: Bound to 0.0.0.0 (all interfaces). Ensure a secure firewall/TLS reverse proxy is active.");
    }

    // Register POSIX signal handlers
#if defined(__linux__)
    struct sigaction sa{};
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGHUP, &sa, nullptr);
#else
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);
#endif

    // Start background metrics collection
    auto collector = std::make_shared<argus::MetricsCollector>(config.monitoring);
    collector->start();

    // Initialize REST API Server
    auto server = std::make_unique<argus::ApiServer>(config, collector);
    g_server_ptr.store(server.get());

    // Bind socket prior to privilege drop
    if (!server->bind()) {
        LOG_ERROR("Fatal: Failed to bind REST API server socket.");
        collector->stop();
        return 1;
    }

    // Drop privileges to unprivileged user if configured and running as root
    if (config.security.drop_privileges.enabled) {
        if (!argus::PrivilegeManager::drop_privileges(
                config.security.drop_privileges.user,
                config.security.drop_privileges.group)) {
            LOG_ERROR("Fatal: Failed to drop privileges to '", config.security.drop_privileges.user, "'. Aborting for safety.");
            collector->stop();
            return 1;
        }
    }

    LOG_INFO("Argus Daemon initialized successfully. Ready to serve requests.");

    // Enter server listening loop (blocks until stopped or signal received)
    server->listen();

    // Clean teardown
    LOG_INFO("Shutting down Argus Daemon...");
    collector->stop();
    g_server_ptr.store(nullptr);

    LOG_INFO("Argus Daemon exited cleanly. Goodbye.");
    return 0;
}
