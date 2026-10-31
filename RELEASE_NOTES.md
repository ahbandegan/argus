# Argus v1.0.0 Release Notes

**Release Name:** Argus v1.0.0 GA ("Panoptes")  
**Release Date:** October 31, 2026  
**Target Operating Systems:** Linux (Ubuntu 22.04+, Debian 11+, RHEL/Rocky 9+, Arch Linux, SUSE)  
**Binary Architecture:** `x86_64`, `aarch64` (ARM64)  
**License:** MIT  

---

## Executive Summary

Argus v1.0.0 marks the initial General Availability (GA) release of **Argus**, a modern, lightweight, and zero-trust hardened system monitoring daemon written in Modern C++ (C++20). Engineered specifically for Linux environments requiring high-frequency telemetry without the runtime overhead, memory footprint, or garbage-collection pauses of Go- or Python-based agents, Argus delivers microsecond-level REST API response times and direct kernel ingestion via `/proc` and Linux syscalls.

---

## Key Highlights & Features

### 1. High-Performance C++20 Core
- **Zero Memory Leaks & Modern RAII**: Built strictly adhering to C++20 standards using smart pointers (`std::unique_ptr`, `std::shared_ptr`), `std::string_view`, concepts, and RAII locks.
- **Asynchronous Telemetry Engine**: Telemetry sampling is isolated on a dedicated background collector thread. Metrics snapshots are synchronized with reader-writer locks (`std::shared_mutex`). API requests never block waiting for disk or kernel file reads, yielding **sub-50 microsecond** response times.
- **Minimal Footprint**: Operates with a Resident Set Size (RSS) under **8 MB** and consumes less than **0.2% CPU** under default 1-second sampling intervals.

### 2. Deep Kernel Telemetry Ingestion
- **CPU Metrics**: Overall utilization and per-core breakdown (User, System, Idle, IOWait, Steal) derived from jiffies arithmetic on `/proc/stat`.
- **Memory & Swap Telemetry**: Real-time memory consumption parsed from `/proc/meminfo` accounting for `MemTotal`, `MemFree`, `MemAvailable`, `Buffers`, `Cached`, `Shmem`, and `SReclaimable`.
- **Filesystem & Disk I/O Rates**: Block and inode statistics via `statvfs()` filtered for real block devices, combined with `/proc/diskstats` sector mathematics to compute instantaneous read/write IOPS and throughput (KB/s and MB/s).
- **Network Interface Traffic**: Ingests `/proc/net/dev` to report cumulative RX/TX bytes and packets alongside instantaneous bandwidth rates per interface.
- **Socket Connection Audit & Process Attribution**:
  - Live socket monitoring across TCP, TCP6, UDP, and UDP6.
  - Automatically resolves socket inodes (`socket:[<inode>]`) to process IDs (**PID**) and process names by traversing `/proc/<pid>/fd`.
  - In-memory circular audit ring buffer tracking newly observed inbound and outbound client connections.

### 3. Zero-Trust Security & Hardening Model
- **Constant-Time Bearer Authentication**: Custom constant-time comparison prevents timing side-channel attacks when validating Bearer tokens.
- **Token Bucket Rate Limiting**: Embedded per-IP rate limiter (default: 120 req/min, burst 30) prevents brute-force attacks and DoS. Returns standard HTTP `429 Too Many Requests` with `Retry-After` headers.
- **POSIX Privilege Dropping**: Ability to bind to low ports or initialize as `root`, then permanently drop UID, GID, and supplementary groups to the unprivileged `argus_svc` service account, verifying that `setuid(0)` fails with `EPERM`.
- **Production systemd Sandboxing**: The bundled `argus.service` enforces Linux kernel namespaces and restrictions:
  - `ProtectSystem=strict`
  - `ProtectHome=true`
  - `PrivateTmp=true`
  - `NoNewPrivileges=true`
  - `MemoryDenyWriteExecute=true`
  - `AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_DAC_READ_SEARCH`

---

## REST API Specifications

All endpoints serve `application/json; charset=utf-8` and require `Authorization: Bearer <TOKEN>` (with the exception of `/api/v1/health` when configured for unauthenticated liveness probes).

| Endpoint | Method | Authentication | Description |
|---|---|---|---|
| `/api/v1/health` | `GET` | Optional | Service status, daemon uptime, system uptime, and version. |
| `/api/v1/overview` | `GET` | Required | Single-pane dashboard consolidating hardware, network, and load metrics. |
| `/api/v1/metrics/hardware` | `GET` | Required | In-depth CPU (overall & per core), RAM/Swap, filesystems, and Disk IOPS. |
| `/api/v1/metrics/network` | `GET` | Required | Current bandwidth rates and cumulative transfer counters per interface. |
| `/api/v1/audit/connections` | `GET` | Required | Active socket table with PID attribution and recent connection audit log. |

---

## Installation & Deployment

### Automated Deployment (`install.sh`)
The automated installer provisions dependencies, compiles in `-O3` Release mode, creates the `argus_svc` system user, generates a 256-bit cryptographic API token, registers the hardened systemd unit, and starts the service:

```bash
chmod +x install.sh
sudo ./install.sh
```

### Configuration (`/etc/argus/config.json`)
```json
{
  "server": {
    "bind_address": "127.0.0.1",
    "port": 9100,
    "threads": 4,
    "require_auth_for_health": false
  },
  "security": {
    "api_token": "<GENERATED_32_BYTE_HEX_TOKEN>",
    "rate_limit": {
      "enabled": true,
      "requests_per_minute": 120,
      "burst_capacity": 30
    },
    "drop_privileges": {
      "enabled": true,
      "user": "argus_svc",
      "group": "argus_svc"
    },
    "tls": {
      "enabled": false,
      "cert_file": "/etc/argus/certs/server.crt",
      "key_file": "/etc/argus/certs/server.key"
    }
  },
  "monitoring": {
    "sample_interval_ms": 1000,
    "connection_audit_history_size": 1000,
    "disk_mount_filter": ["/", "/home", "/var"]
  },
  "logging": {
    "level": "INFO",
    "log_file": "/var/log/argus/argus.log"
  }
}
```

---

## Upgrade & Migration Notes

- **Initial Release**: This is the first public release; no migrations are required.
- **Port Assignment**: By default, Argus binds to `127.0.0.1:9100`. If running concurrently with Prometheus `node_exporter`, configure `server.port` to another port (e.g., `9105`) or use the `-p <port>` CLI flag.

---

## Verification & Smoke Test

```bash
# 1. Health check
curl -s http://127.0.0.1:9100/api/v1/health | jq

# 2. Authenticated overview
curl -s -H "Authorization: Bearer <YOUR_API_TOKEN>" http://127.0.0.1:9100/api/v1/overview | jq
```

---

*Argus Project Core Team — Security & Systems Engineering Group*
