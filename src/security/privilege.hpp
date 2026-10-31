#pragma once

#include <string>

namespace argus {

class PrivilegeManager {
public:
    // Drops process privileges to the specified user and group.
    // Must be called after privileged operations (e.g. low-port binding) are completed.
    // Returns true on success (or if already unprivileged), false on failure.
    static bool drop_privileges(const std::string& username, const std::string& groupname);

    // Checks whether the current process is running as root (UID 0)
    [[nodiscard]] static bool is_running_as_root() noexcept;

    // Returns current UID and user name
    [[nodiscard]] static std::string get_current_user_info();
};

} // namespace argus
