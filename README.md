# traffic-agent

A Go application that passively intercepts and inspects **HTTP and HTTPS** network traffic at the kernel level using **eBPF**, without acting as a proxy or requiring any changes to client applications.

- **HTTP** — captured via TC (Traffic Control) eBPF hooks on the network interface
- **HTTPS** — captured via eBPF uprobes on OpenSSL's `SSL_read`/`SSL_write`, intercepting plaintext before encryption and after decryption with no certificate injection or MITM

---

## Table of Contents

- [How It Works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Building](#building)
- [Running](#running)
- [HTTPS / TLS Interception](#https--tls-interception)
- [Configuration Reference](#configuration-reference)
- [Output Format](#output-format)
- [Event Streaming](#event-streaming)
- [Systemd Installation](#systemd-installation)
- [Required Capabilities](#required-capabilities)
- [Makefile Targets](#makefile-targets)
- [Known Limitations](#known-limitations)

---

## How It Works

```
                  ┌─────────────────────────────────────────────┐
                  │              Kernel Space                    │
  ┌──────┐        │  ┌─────────────┐   ┌─────────────────────┐  │
  │ NIC  │──eth0──│  │  TC ingress │   │  TC egress          │  │
  └──────┘        │  │  (BPF prog) │   │  (BPF prog)         │  │
                  │  └──────┬──────┘   └──────────┬──────────┘  │
                  │         │  ring buffer          │             │
                  └─────────┼───────────────────────┼────────────┘
                            │                       │
                  ┌─────────▼───────────────────────▼────────────┐
                  │              User Space (Go)                  │
                  │                                               │
                  │  ┌─────────────┐   ┌─────────────────────┐  │
                  │  │  TC Capture │   │  SSL Interceptor     │  │
                  │  │  (capture/) │   │  (tls/)              │  │
                  │  └──────┬──────┘   └──────────┬──────────┘  │
                  │         │ RawPacketEvent        │ SSLEvent    │
                  │  ┌──────▼──────────────────────▼───────┐    │
                  │  │       HTTP Parser (parser/)           │    │
                  │  │  per-flow buffering + net/http parse  │    │
                  │  └─────────────────────┬─────────────────┘   │
                  │                        │ TrafficEvent         │
                  │              ┌─────────▼──────────┐          │
                  │              │   Filter (filter/)  │          │
                  │              └─────────┬──────────┘          │
                  │                        │                      │
                  │         ┌──────────────┼──────────────┐      │
                  │         ▼              ▼              ▼       │
                  │   ┌───────────┐  ┌──────────┐  ┌──────────┐  │
                  │   │  Logger   │  │ Streamer │  │ (future) │  │
                  │   │ (output/) │  │ HTTP SSE │  │          │  │
                  │   └───────────┘  └──────────┘  └──────────┘  │
                  └───────────────────────────────────────────────┘
```

**TC (Traffic Control) hooks** are attached to both the ingress and egress paths of a network interface. Every TCP packet matching the configured ports passes through the BPF program, which copies the payload into a ring buffer. The Go userspace process reads from the ring buffer, accumulates per-flow payloads, and parses complete HTTP/1.1 request and response messages. Parsed events are filtered, then written as newline-delimited JSON.

| Hook | Direction | What is captured |
|------|-----------|-----------------|
| TC ingress | Inbound | Server → client responses (status code, headers, body) |
| TC egress | Outbound | Client → server requests (method, URL, headers, body) |
| uprobe SSL_write / SSL_read | Both | Plaintext before/after OpenSSL encryption (TLS interception, optional) |

---

## Prerequisites

### System packages

```bash
# Ubuntu / Debian
sudo apt-get install -y \
    clang llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    linux-tools-$(uname -r)   # provides bpftool

# Verify BTF support (required for CO-RE)
ls /sys/kernel/btf/vmlinux
```

### Go toolchain

```bash
# Go 1.22 or later
go version

# Install bpf2go (used by go generate to compile eBPF C programs)
go install github.com/cilium/ebpf/cmd/bpf2go@latest
```

### Kernel requirements

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| Kernel version | 5.8 | CO-RE + BTF support |
| Kernel version | 5.11 | Recommended — removes `RLIMIT_MEMLOCK` restriction |
| `CONFIG_DEBUG_INFO_BTF` | `y` | Required for `vmlinux.h` generation |

```bash
# Check kernel version and BTF config
uname -r
grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)
```

---

## Building

```bash
# 1. Clone
git clone https://github.com/code-8888888888/traffic-agent
cd traffic-agent

# 2. Generate vmlinux.h from the running kernel (one-time per machine)
make vmlinux

# 3. Fetch Go dependencies
make tidy

# 4. Compile eBPF C → Go objects, then build binary
make build
# Output: ./bin/traffic-agent
```

To rebuild after changing only Go code (skips BPF recompilation):

```bash
go build -o ./bin/traffic-agent ./cmd/agent
```

---

## Running

```bash
# Run directly (requires root or the capabilities listed below)
sudo ./bin/traffic-agent --config config/config.yaml

# Flags
sudo ./bin/traffic-agent --help
  -config string   path to config.yaml (default "/etc/traffic-agent/config.yaml")
  -v               verbose logging
```

Traffic events are written as newline-delimited JSON to stdout (and optionally to a file). Log messages (startup, errors) go to stderr.

```bash
# Capture events to a file while watching logs in real time
sudo ./bin/traffic-agent --config config/config.yaml \
    > /var/log/traffic-agent/events.json \
    2> /var/log/traffic-agent/agent.log
```

---

## HTTPS / TLS Interception

The agent hooks into OpenSSL's `SSL_write` and `SSL_read` functions via eBPF uprobes to capture plaintext **before encryption** (outbound) and **after decryption** (inbound). No certificate injection, no MITM proxy, and no changes to the client are required.

### How it works

```
curl → SSL_write(plaintext request) → [uprobe fires, copies to ring buffer]
                                     → OpenSSL encrypts → sends over wire

wire → OpenSSL decrypts → SSL_read(plaintext response) → [uprobe fires, copies to ring buffer]
```

The captured plaintext is fed into the same HTTP/1.1 parser as TC-captured traffic, producing `TrafficEvent` JSON with `"protocol": "TLS"` and `"tls_intercepted": true`.

### Enabling TLS interception

Set `tls.enabled: true` in `config.yaml` (it is enabled in the default config):

```yaml
tls:
  enabled: true
  # No pids or processes = attach globally to all processes using libssl.so
```

When no `pids` or `processes` are specified, the agent attaches system-wide to `libssl.so.3`, intercepting all processes that use OpenSSL on the machine.

### Testing

```bash
# Start the agent
sudo ./bin/traffic-agent --config config/config.yaml

# In another terminal — use --http1.1 to avoid HTTP/2 binary framing
curl --http1.1 https://httpbin.org/get
curl --http1.1 https://httpbin.org/post -H 'Content-Type: application/json' -d '{"hello":"world"}'
```

### Example output

```json
{"timestamp":"2026-02-22T14:58:39.270923093Z","src_ip":"","dst_ip":"","src_port":0,"dst_port":0,"protocol":"TLS","direction":"egress","pid":349147,"process_name":"curl","http_method":"POST","url":"/post","request_headers":{"Accept":"*/*","Content-Length":"17","Content-Type":"application/json","Host":"httpbin.org","User-Agent":"curl/7.81.0"},"body_snippet":"{\"hello\":\"world\"}","tls_intercepted":true}
{"timestamp":"2026-02-22T14:58:39.798016124Z","src_ip":"","dst_ip":"","src_port":0,"dst_port":0,"protocol":"TLS","direction":"ingress","pid":349147,"process_name":"curl","status_code":200,"response_headers":{"Content-Length":"434","Content-Type":"application/json","Server":"gunicorn/19.9.0"},"body_snippet":"{\n  \"data\": \"{\\\"hello\\\":\\\"world\\\"}\", ...}","tls_intercepted":true}
```

> **Note:** `src_ip`/`dst_ip`/`src_port`/`dst_port` are empty for TLS events — IP/port information is not available at the SSL uprobe level. Use TC-captured events (plain HTTP on port 80) when you need connection-level metadata.

### HTTP/2 caveat

By default, curl negotiates HTTP/2 for HTTPS connections. HTTP/2 uses binary HPACK framing which is not parseable by the HTTP/1.1 parser. Force HTTP/1.1 to get clean events:

```bash
curl --http1.1 https://example.com/api
```

HTTP/2 support is tracked in [Known Limitations](#known-limitations).

### Target-specific attachment

To intercept only a specific process rather than all SSL traffic:

```yaml
tls:
  enabled: true
  processes:
    - nginx      # attach only to processes named "nginx"
    - python3
  # or by PID:
  # pids:
  #   - 1234
```

### Go TLS limitation

Go programs use the built-in `crypto/tls` package, which does **not** link against OpenSSL. SSL uprobes do not cover Go HTTPS clients or servers. See [Known Limitations](#known-limitations).

---

## Configuration Reference

The config file is YAML. The default path is `/etc/traffic-agent/config.yaml`; override with `--config`.

All fields are optional — defaults are shown in the comments below.

```yaml
# -----------------------------------------------------------------------
# Interface
# -----------------------------------------------------------------------

# Network interface to attach TC eBPF hooks to.
# Run `ip link show` to find the correct name on your system.
# Default: eth0
interface: enp0s1


# -----------------------------------------------------------------------
# Port filter (BPF-level, applied before any userspace filtering)
# -----------------------------------------------------------------------

# TCP ports to capture. Only packets whose source OR destination port
# matches one of these values are passed through the BPF program.
# All other ports are ignored at the kernel level (zero overhead).
# Default: [80, 443, 8080, 8443]
ports:
  - 80     # HTTP
  - 443    # HTTPS
  - 8080   # HTTP alternate
  - 8443   # HTTPS alternate


# -----------------------------------------------------------------------
# Traffic filtering  (userspace, applied after BPF capture)
# All rules are ANDed. An empty or omitted rule matches everything.
# -----------------------------------------------------------------------

filter:
  # Capture only packets from these source IP addresses.
  # Accepts exact IPv4 addresses (CIDR notation not yet supported).
  # Default: [] (match all sources)
  # src_ips:
  #   - 10.0.0.5
  #   - 192.168.1.10

  # Capture only packets destined for these IP addresses.
  # Default: [] (match all destinations)
  # dst_ips:
  #   - 93.184.216.34

  # Capture only packets from these source ports.
  # Useful to pin to a specific client ephemeral port for debugging.
  # Default: [] (match all source ports)
  # src_ports:
  #   - 54321

  # Capture only packets destined for these ports.
  # Narrows down within the BPF-level port list above.
  # Default: [] (match all destination ports)
  # dst_ports:
  #   - 80

  # Capture only traffic from these process IDs.
  # PID filtering is best-effort; PIDs can be reused by the OS.
  # Default: [] (match all processes)
  # pids:
  #   - 1234
  #   - 5678

  # Capture only traffic from processes with these names.
  # Matched against the comm name (/proc/<pid>/comm, max 15 chars).
  # Default: [] (match all process names)
  # processes:
  #   - curl
  #   - nginx
  #   - python3


# -----------------------------------------------------------------------
# Output / logging
# -----------------------------------------------------------------------

output:
  # Write JSON events to stdout.
  # Default: true (also forced true when no file is configured)
  stdout: true

  # Write JSON events to a rotating log file.
  # Leave empty to disable file logging.
  # Default: "" (disabled)
  # file: /var/log/traffic-agent/events.json

  # Maximum size of the log file in megabytes before rotation.
  # Default: 100
  max_size_mb: 100

  # Maximum number of days to retain old rotated log files.
  # 0 means retain indefinitely.
  # Default: 7
  max_age_days: 7

  # Maximum number of old rotated log files to keep.
  # 0 means keep all.
  # Default: 3
  max_backups: 3

  # Gzip-compress rotated log files to save disk space.
  # Default: false
  compress: false


# -----------------------------------------------------------------------
# TLS / SSL plaintext interception via eBPF uprobes  (optional)
# Hooks into OpenSSL's SSL_read / SSL_write to capture plaintext
# before encryption and after decryption — no certificate injection.
# -----------------------------------------------------------------------

tls:
  # Enable SSL uprobe interception.
  # Default: false
  enabled: false

  # Attach uprobes only to these process IDs.
  # If empty (and enabled: true), attaches to all processes using libssl.
  # Default: [] (all processes)
  # pids:
  #   - 1234

  # Attach uprobes only to processes with these names.
  # Default: [] (all processes)
  # processes:
  #   - nginx
  #   - envoy

  # Explicit path to libssl.so.
  # Leave empty to auto-detect via /proc/<pid>/maps (recommended).
  # Default: "" (auto-detect)
  # libssl_path: /usr/lib/x86_64-linux-gnu/libssl.so.3


# -----------------------------------------------------------------------
# HTTP event streaming endpoint  (optional)
# Exposes a local HTTP server that streams captured events as
# newline-delimited JSON (ndjson) for downstream consumers.
# -----------------------------------------------------------------------

event_stream:
  # Enable the streaming HTTP server.
  # Default: false
  enabled: false

  # TCP address to listen on.
  # Default: 127.0.0.1:8080
  address: "127.0.0.1:8080"

  # HTTP path for the event stream.
  # Default: /events
  path: /events
```

---

## Output Format

Each captured HTTP transaction produces one or two JSON lines on stdout (and/or the log file): one for the **request** and one for the **response**.

### Request event

```json
{
  "timestamp": "2026-02-22T14:34:02.764229109Z",
  "src_ip": "192.168.68.62",
  "dst_ip": "44.195.71.76",
  "src_port": 42126,
  "dst_port": 80,
  "protocol": "TCP",
  "direction": "egress",
  "http_method": "POST",
  "url": "/api/data",
  "request_headers": {
    "Accept": "*/*",
    "Content-Length": "17",
    "Content-Type": "application/json",
    "Host": "example.com",
    "User-Agent": "curl/7.81.0"
  },
  "body_snippet": "{\"hello\":\"world\"}"
}
```

### Response event

```json
{
  "timestamp": "2026-02-22T14:34:02.981524882Z",
  "src_ip": "44.195.71.76",
  "dst_ip": "192.168.68.62",
  "src_port": 80,
  "dst_port": 42126,
  "protocol": "TCP",
  "direction": "ingress",
  "status_code": 200,
  "response_headers": {
    "Content-Length": "256",
    "Content-Type": "application/json",
    "Date": "Sun, 22 Feb 2026 14:34:02 GMT",
    "Server": "gunicorn/19.9.0"
  },
  "body_snippet": "{\n  \"args\": {},\n  \"origin\": \"103.157.123.210\"\n}\n"
}
```

### Field reference

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | string (RFC3339Nano) | Wall-clock time the event was emitted |
| `src_ip` | string | Source IPv4 address |
| `dst_ip` | string | Destination IPv4 address |
| `src_port` | number | Source TCP port |
| `dst_port` | number | Destination TCP port |
| `protocol` | string | `"TCP"` for TC-captured events; `"TLS"` for SSL-uprobe events |
| `direction` | string | `"egress"` (outbound request) or `"ingress"` (inbound response) |
| `http_method` | string | HTTP method (`GET`, `POST`, …) — requests only |
| `url` | string | Request path and query string — requests only |
| `request_headers` | object | All HTTP request headers including `Host` — requests only |
| `status_code` | number | HTTP response status code — responses only |
| `response_headers` | object | All HTTP response headers — responses only |
| `body_snippet` | string | First 512 bytes of the request or response body (omitted if empty) |
| `pid` | number | Process ID (populated for SSL-uprobe events; omitted for TC events) |
| `process_name` | string | Process name (populated for SSL-uprobe events; omitted for TC events) |
| `tls_intercepted` | bool | `true` when the payload came from an SSL uprobe (omitted otherwise) |

---

## Event Streaming

Enable the streaming endpoint in config, then subscribe with any HTTP client:

```yaml
event_stream:
  enabled: true
  address: "127.0.0.1:9000"
  path: /events
```

```bash
# Subscribe — events arrive as newline-delimited JSON
curl -N http://127.0.0.1:9000/events

# Pipe into jq for pretty-printing
curl -sN http://127.0.0.1:9000/events | jq .

# Filter to POST requests only
curl -sN http://127.0.0.1:9000/events | jq 'select(.http_method == "POST")'
```

Multiple concurrent subscribers are supported; each receives all events independently.

---

## Systemd Installation

```bash
# Build and install binary, default config, and service unit
sudo make install

# Enable and start
sudo systemctl enable --now traffic-agent

# Check status
sudo systemctl status traffic-agent

# Follow logs
sudo journalctl -u traffic-agent -f

# Reload config (restart required — no hot reload)
sudo systemctl restart traffic-agent

# Uninstall (config and logs are preserved)
sudo make uninstall
```

`make install` installs to:

| Path | Contents |
|------|----------|
| `/usr/local/bin/traffic-agent` | Binary |
| `/etc/traffic-agent/config.yaml` | Default config (only if not already present) |
| `/var/log/traffic-agent/` | Log directory |
| `/etc/systemd/system/traffic-agent.service` | Systemd unit |

---

## Required Capabilities

The agent requires elevated privileges to load eBPF programs and attach TC filters.

| Capability | Required for |
|-----------|-------------|
| `CAP_BPF` | Loading eBPF programs and creating maps |
| `CAP_NET_ADMIN` | Attaching TC filters to network interfaces |
| `CAP_SYS_ADMIN` | eBPF operations on kernels older than 5.8 |
| `CAP_SYS_PTRACE` | Reading `/proc/<pid>/maps` for SSL uprobe symbol resolution |

### Option 1: Run as root (default)

The systemd unit runs as `root` by default. No additional setup is required.

### Option 2: Dedicated user with ambient capabilities

```bash
# Create a dedicated system user
sudo useradd -r -s /sbin/nologin traffic-agent

# Grant capabilities to the binary
sudo setcap 'cap_bpf,cap_net_admin,cap_sys_admin,cap_sys_ptrace+eip' \
    /usr/local/bin/traffic-agent
```

Then edit `/etc/systemd/system/traffic-agent.service` and uncomment the capability block:

```ini
User=traffic-agent
Group=traffic-agent
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN CAP_NET_RAW
```

---

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make build` | Compile eBPF C programs and build the binary to `./bin/traffic-agent` |
| `make generate` | Compile BPF C → Go-embedded objects only (runs `bpf2go`) |
| `make vmlinux` | Generate `bpf/headers/vmlinux.h` from the running kernel's BTF |
| `make tidy` | Run `go mod tidy` |
| `make install` | Install binary, config, and systemd service (requires root) |
| `make uninstall` | Remove installed binary and service (preserves config and logs) |
| `make lint` | Run `golangci-lint` |
| `make test` | Run unit tests with race detector |
| `make clean` | Remove `./bin/` and generated eBPF Go bindings |

---

## Known Limitations

1. **IPv4 only** — The TC BPF program skips non-`ETH_P_IP` frames. IPv6 support requires adding `ip6hdr` parsing.

2. **HTTP/1.1 only** — HTTP/2 uses binary HPACK framing and is not parsed. When using SSL uprobes with curl, pass `--http1.1` to force HTTP/1.1 negotiation. HTTP/2 support would require an additional HPACK framing layer on top of the SSL uprobe capture path.

3. **TCP sequence numbers not captured** — Payloads are accumulated in arrival order. Out-of-order segment reassembly is not supported. In practice, in-order delivery is the common case on local networks.

4. **Body snippet limit** — At most 512 bytes of the request or response body are captured per event (`BodySnippetMaxLen` in `internal/types/types.go`). Large bodies are truncated.

5. **BPF ring buffer size** — The TC ring buffer is 256 KiB (`max_entries` in `bpf/tc_capture.c`). Under sustained high throughput, events may be dropped. Increase `max_entries` and recompile if needed.

6. **Go TLS not intercepted** — Go's `crypto/tls` does not link against OpenSSL, so the SSL uprobes do not cover Go HTTPS clients or servers. A separate uretprobe on `crypto/tls.(*Conn).Read/Write` is planned.

7. **Per-interface attachment** — TC hooks attach to one interface. Capture on multiple interfaces requires running multiple instances with different configs, or extending the code to iterate over interfaces.

8. **Container traffic** — The TC hook captures at the host interface level. Traffic between containers on a Docker bridge network is visible at the `docker0` interface, not `eth0`. Set `interface: docker0` (or the relevant veth) to capture container traffic.

9. **Kernel version** — Developed and tested on Linux 5.15 (ARM64). CO-RE requires kernel 5.8+ with `CONFIG_DEBUG_INFO_BTF=y`.
