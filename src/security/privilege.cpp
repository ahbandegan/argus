#include "privilege.hpp"
#include "../common/logger.hpp"

#if defined(__linux__)
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <cerrno>
#include <cstring>
#endif

namespace argus {

bool PrivilegeManager::is_running_as_root() noexcept {
#if defined(__linux__)
    return (getuid() == 0 || geteuid() == 0);
#else
    return false;
#endif
}

std::string PrivilegeManager::get_current_user_info() {
#if defined(__linux__)
    uid_t uid = getuid();
    struct passwd* pw = getpwuid(uid);
    std::string name = (pw && pw->pw_name) ? pw->pw_name : "unknown";
    return name + " (UID " + std::to_string(uid) + ")";
#else
    return "non-linux (unprivileged)";
#endif
}

bool PrivilegeManager::drop_privileges(const std::string& username, const std::string& groupname) {
#if defined(__linux__)
    if (!is_running_as_root()) {
        LOG_INFO("Privilege drop: Already running as unprivileged user: ", get_current_user_info());
        return true;
    }

    LOG_INFO("Privilege drop requested. Target user: '", username, "', group: '", groupname, "'");

    // Look up target group
    struct group* gr = getgrnam(groupname.c_str());
    if (!gr) {
        LOG_ERROR("Privilege drop failed: Group '", groupname, "' does not exist: ", std::strerror(errno));
        return false;
    }
    gid_t target_gid = gr->gr_gid;

    // Look up target user
    struct passwd* pw = getpwnam(username.c_str());
    if (!pw) {
        LOG_ERROR("Privilege drop failed: User '", username, "' does not exist: ", std::strerror(errno));
        return false;
    }
    uid_t target_uid = pw->pw_uid;

    // 1. Drop supplementary groups
    if (initgroups(username.c_str(), target_gid) != 0) {
        LOG_WARN("initgroups failed: ", std::strerror(errno), ". Falling back to setgroups.");
        if (setgroups(1, &target_gid) != 0) {
            LOG_ERROR("Failed to drop supplementary groups: ", std::strerror(errno));
            return false;
        }
    }

    // 2. Set GID
    if (setgid(target_gid) != 0) {
        LOG_ERROR("Failed to setgid to ", target_gid, ": ", std::strerror(errno));
        return false;
    }

    // 3. Set UID
    if (setuid(target_uid) != 0) {
        LOG_ERROR("Failed to setuid to ", target_uid, ": ", std::strerror(errno));
        return false;
    }

    // 4. Verification: verify we can no longer regain root
    if (setuid(0) != -1) {
        LOG_ERROR("SECURITY FAILURE: Successfully regained root UID after privilege drop!");
        return false;
    }

    if (getuid() != target_uid || geteuid() != target_uid) {
        LOG_ERROR("SECURITY FAILURE: Target UID does not match after setuid! Effective: ", geteuid());
        return false;
    }

    LOG_INFO("Privileges successfully dropped to unprivileged user: ", username, " (UID: ", target_uid, ", GID: ", target_gid, ")");
    return true;
#else
    LOG_INFO("Privilege dropping is a Linux-specific feature. Running as current user.");
    (void)username;
    (void)groupname;
    return true;
#endif
}

} // namespace argus
