#pragma once

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <memory>

namespace argus {

enum class LogLevel {
    DEBUG = 0,
    INFO,
    WARN,
    ERROR
};

class Logger {
public:
    static Logger& instance() {
        static Logger instance;
        return instance;
    }

    void set_level(LogLevel level) noexcept {
        min_level_ = level;
    }

    void set_level_from_string(std::string_view level_str) noexcept {
        if (level_str == "DEBUG" || level_str == "debug") min_level_ = LogLevel::DEBUG;
        else if (level_str == "INFO" || level_str == "info") min_level_ = LogLevel::INFO;
        else if (level_str == "WARN" || level_str == "warn") min_level_ = LogLevel::WARN;
        else if (level_str == "ERROR" || level_str == "error") min_level_ = LogLevel::ERROR;
    }

    void set_log_file(const std::string& path) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (file_stream_.is_open()) {
            file_stream_.close();
        }
        file_stream_.open(path, std::ios::out | std::ios::app);
        if (!file_stream_.is_open()) {
            std::cerr << "[Argus Logger] Failed to open log file: " << path << std::endl;
        }
    }

    template <typename... Args>
    void log(LogLevel level, std::string_view fmt_prefix, Args&&... args) {
        if (level < min_level_) return;

        std::ostringstream ss;
        (ss << ... << std::forward<Args>(args));
        write_record(level, fmt_prefix, ss.str());
    }

    void debug(std::string_view msg) { log(LogLevel::DEBUG, "", msg); }
    void info(std::string_view msg)  { log(LogLevel::INFO, "", msg); }
    void warn(std::string_view msg)  { log(LogLevel::WARN, "", msg); }
    void error(std::string_view msg) { log(LogLevel::ERROR, "", msg); }

private:
    Logger() : min_level_(LogLevel::INFO) {}
    ~Logger() {
        if (file_stream_.is_open()) {
            file_stream_.close();
        }
    }

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    static const char* level_to_string(LogLevel level) noexcept {
        switch (level) {
            case LogLevel::DEBUG: return "DEBUG";
            case LogLevel::INFO:  return "INFO ";
            case LogLevel::WARN:  return "WARN ";
            case LogLevel::ERROR: return "ERROR";
            default:              return "UNKN ";
        }
    }

    static const char* level_color(LogLevel level) noexcept {
        switch (level) {
            case LogLevel::DEBUG: return "\033[36m"; // Cyan
            case LogLevel::INFO:  return "\033[32m"; // Green
            case LogLevel::WARN:  return "\033[33m"; // Yellow
            case LogLevel::ERROR: return "\033[31m"; // Red
            default:              return "\033[0m";
        }
    }

    void write_record(LogLevel level, std::string_view prefix, const std::string& message) {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

        std::tm tm_buf{};
#if defined(_WIN32)
        localtime_s(&tm_buf, &in_time_t);
#else
        localtime_r(&in_time_t, &tm_buf);
#endif

        std::ostringstream time_ss;
        time_ss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S")
                << '.' << std::setfill('0') << std::setw(3) << ms.count();

        std::string time_str = time_ss.str();

        std::lock_guard<std::mutex> lock(mutex_);

        // Write to stdout / stderr with color
        auto& out_stream = (level == LogLevel::ERROR) ? std::cerr : std::cout;
        out_stream << "\033[90m[" << time_str << "]\033[0m "
                   << level_color(level) << "[" << level_to_string(level) << "]\033[0m "
                   << (prefix.empty() ? "" : "[") << (prefix.empty() ? "" : prefix) << (prefix.empty() ? "" : "] ")
                   << message << std::endl;

        // Write to log file if configured (strip colors)
        if (file_stream_.is_open()) {
            file_stream_ << "[" << time_str << "] [" << level_to_string(level) << "] "
                         << (prefix.empty() ? "" : "[") << (prefix.empty() ? "" : prefix) << (prefix.empty() ? "" : "] ")
                         << message << std::endl;
            file_stream_.flush();
        }
    }

    LogLevel min_level_;
    std::mutex mutex_;
    std::ofstream file_stream_;
};

#define LOG_DEBUG(...) ::argus::Logger::instance().log(::argus::LogLevel::DEBUG, "Argus", __VA_ARGS__)
#define LOG_INFO(...)  ::argus::Logger::instance().log(::argus::LogLevel::INFO,  "Argus", __VA_ARGS__)
#define LOG_WARN(...)  ::argus::Logger::instance().log(::argus::LogLevel::WARN,  "Argus", __VA_ARGS__)
#define LOG_ERROR(...) ::argus::Logger::instance().log(::argus::LogLevel::ERROR, "Argus", __VA_ARGS__)

} // namespace argus
