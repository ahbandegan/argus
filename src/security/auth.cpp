#include "auth.hpp"
#include <httplib.h>
#include <algorithm>
#include <cctype>

namespace argus {

namespace {

std::string_view trim_string(std::string_view s) noexcept {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
        ++start;
    }
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
        --end;
    }
    return s.substr(start, end - start);
}

} // anonymous namespace

TokenAuthenticator::TokenAuthenticator(std::string expected_token)
    : expected_token_(std::move(expected_token)) {}

bool TokenAuthenticator::constant_time_compare(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }

    volatile unsigned char result = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        result |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return result == 0;
}

bool TokenAuthenticator::validate_token(std::string_view client_token) const noexcept {
    if (expected_token_.empty()) {
        // If no token is configured, fail closed
        return false;
    }
    return constant_time_compare(client_token, expected_token_);
}

bool TokenAuthenticator::authenticate(const httplib::Request& req) const noexcept {
    if (expected_token_.empty()) {
        return false;
    }

    // 1. Check Authorization: Bearer <token>
    if (req.has_header("Authorization")) {
        std::string auth_header = req.get_header_value("Authorization");
        std::string_view auth_view = trim_string(auth_header);

        constexpr std::string_view bearer_prefix = "Bearer ";
        if (auth_view.size() > bearer_prefix.size()) {
            bool prefix_matches = true;
            for (size_t i = 0; i < bearer_prefix.size(); ++i) {
                if (std::tolower(static_cast<unsigned char>(auth_view[i])) !=
                    std::tolower(static_cast<unsigned char>(bearer_prefix[i]))) {
                    prefix_matches = false;
                    break;
                }
            }

            if (prefix_matches) {
                std::string_view token_part = trim_string(auth_view.substr(bearer_prefix.size()));
                if (validate_token(token_part)) {
                    return true;
                }
            }
        }
    }

    // 2. Check fallback header X-API-Key: <token>
    if (req.has_header("X-API-Key")) {
        std::string key_header = req.get_header_value("X-API-Key");
        std::string_view key_view = trim_string(key_header);
        if (validate_token(key_view)) {
            return true;
        }
    }

    return false;
}

} // namespace argus
