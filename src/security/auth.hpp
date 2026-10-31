#pragma once

#include <string>
#include <string_view>

namespace httplib {
    struct Request;
}

namespace argus {

class TokenAuthenticator {
public:
    explicit TokenAuthenticator(std::string expected_token);
    ~TokenAuthenticator() = default;

    // Disallow accidental copies containing secrets
    TokenAuthenticator(const TokenAuthenticator&) = delete;
    TokenAuthenticator& operator=(const TokenAuthenticator&) = delete;
    TokenAuthenticator(TokenAuthenticator&&) noexcept = default;
    TokenAuthenticator& operator=(TokenAuthenticator&&) noexcept = default;

    // Validates Bearer token from HTTP headers in constant time
    [[nodiscard]] bool authenticate(const httplib::Request& req) const noexcept;
    [[nodiscard]] bool validate_token(std::string_view client_token) const noexcept;

    // Constant-time string comparison to eliminate timing side-channel attacks
    [[nodiscard]] static bool constant_time_compare(std::string_view a, std::string_view b) noexcept;

    [[nodiscard]] bool is_configured() const noexcept {
        return !expected_token_.empty();
    }

private:
    std::string expected_token_;
};

} // namespace argus
