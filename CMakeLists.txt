cmake_minimum_required(VERSION 3.20)
project(argus VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set build type to Release by default if not set
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose build type: Debug Release RelWithDebInfo MinSizeRel" FORCE)
endif()

include(FetchContent)

# 1. nlohmann/json
find_package(nlohmann_json 3.10 QUIET)
if(NOT nlohmann_json_FOUND)
    message(STATUS "Fetching nlohmann/json v3.11.3...")
    FetchContent_Declare(
        nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG v3.11.3
        GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif()

# 2. cpp-httplib
find_package(httplib QUIET)
if(NOT httplib_FOUND)
    message(STATUS "Fetching cpp-httplib v0.18.3...")
    set(HTTPLIB_REQUIRE_OPENSSL OFF CACHE BOOL "Don't hard-require OpenSSL in httplib" FORCE)
    FetchContent_Declare(
        httplib
        GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
        GIT_TAG v0.18.3
        GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(httplib)
endif()

# 3. Threads
find_package(Threads REQUIRED)

# 4. OpenSSL (Optional: provides direct HTTPS/TLS support)
find_package(OpenSSL QUIET)

# Source files
set(ARGUS_SOURCES
    src/main.cpp
    src/common/config.cpp
    src/metrics/hardware.cpp
    src/metrics/network.cpp
    src/metrics/collector.cpp
    src/security/auth.cpp
    src/security/rate_limiter.cpp
    src/security/privilege.cpp
    src/api/server.cpp
)

add_executable(argus ${ARGUS_SOURCES})

target_include_directories(argus PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(argus PRIVATE
    nlohmann_json::nlohmann_json
    httplib::httplib
    Threads::Threads
)

# OpenSSL integration if available
if(OpenSSL_FOUND)
    message(STATUS "OpenSSL ${OPENSSL_VERSION} found. Enabling TLS/HTTPS support.")
    target_link_libraries(argus PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(argus PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
else()
    message(STATUS "OpenSSL not found. Building with HTTP only (production reverse proxy mode).")
endif()

# Hardening compiler & linker flags on GCC and Clang
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(argus PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -fstack-protector-strong
        $<$<CONFIG:Release>:-O3>
        $<$<CONFIG:Release>:-D_FORTIFY_SOURCE=2>
    )

    if(NOT APPLE AND NOT WIN32)
        target_compile_options(argus PRIVATE -fPIE)
        target_link_options(argus PRIVATE
            -pie
            -Wl,-z,relro
            -Wl,-z,now
            -Wl,-z,noexecstack
        )
    endif()
endif()

# Installation rules
include(GNUInstallDirs)
install(TARGETS argus
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES config.json
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/argus
    RENAME config.json.example
)
