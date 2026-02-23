# traffic-agent

A Go application that passively intercepts and inspects **HTTP and HTTPS** network traffic at the kernel level using **eBPF**, without acting as a proxy or requiring any changes to client applications.

- **HTTP** — captured via TC (Traffic Control) eBPF hooks on the network interface
- **HTTPS / TLS** — captured via eBPF uprobes on SSL library write/read functions, intercepting plaintext before encryption and after decryption with no certificate injection or MITM; automatically detects **OpenSSL, BoringSSL, GnuTLS, and NSS/NSPR** without any per-library configuration

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
| uprobe SSL write / read | Both | Plaintext before/after TLS encryption; auto-attaches to **OpenSSL** (`SSL_write/read`), **BoringSSL** (`SSL_write/read`), **GnuTLS** (`gnutls_record_send/recv`), **NSS/NSPR** (`PR_Write/PR_Read`) |

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

The agent hooks into SSL library write/read functions via eBPF uprobes to capture plaintext **before encryption** (outbound) and **after decryption** (inbound). No certificate injection, no MITM proxy, and no changes to the client are required.

### How it works

```
app → SSL_write(plaintext) → [uprobe fires → ring buffer]
                           → library encrypts → wire

wire → library decrypts → SSL_read(plaintext) → [uprobe fires → ring buffer]
```

The captured plaintext is fed into the HTTP/1.1 parser, producing `TrafficEvent` JSON with `"protocol": "TLS"` and `"tls_intercepted": true`.

### Supported SSL libraries

All four libraries share the same calling convention — `(context, buf, len)` with `buf` at register PARM2 and `len` at PARM3 — so a single BPF program covers all of them without any code changes.

| Library | Shared object | Hooked functions | Common users |
|---------|--------------|-----------------|--------------|
| OpenSSL | `libssl.so` | `SSL_write` / `SSL_read` | curl, wget, nginx, Python, Node.js |
| BoringSSL | `libboringssl.so` | `SSL_write` / `SSL_read` | Some Chromium builds, gRPC |
| GnuTLS | `libgnutls.so` | `gnutls_record_send` / `gnutls_record_recv` | wget, glib networking tools |
| NSS / NSPR | `libnspr4.so` | `PR_Write` / `PR_Read` | Firefox, Thunderbird |

### Auto-detection

When `tls.enabled: true` with no `pids` or `processes` specified, the agent scans **all running processes** via `/proc/*/maps` at startup. For every unique SSL shared library found, it attaches system-wide uprobes (PID 0) so that even processes that start *after* the agent are covered for libraries already attached.

```
[tls] attached global uprobes to libnspr4.so (PR_Write/PR_Read)
[tls] attached global uprobes to libssl.so.3 (SSL_write/SSL_read)
[tls] attached global uprobes to libgnutls.so.30.31.0 (gnutls_record_send/gnutls_record_recv)
[tls] attached BoringSSL uprobes to node (pid=0, dynamic=false, write_off=0x15fa654)
```

### Enabling TLS interception

Set `tls.enabled: true` in `config.yaml` (enabled in the default config):

```yaml
tls:
  enabled: true
  # No pids or processes = attach globally to all processes using any SSL library
```

### Testing

```bash
# Start the agent
sudo ./bin/traffic-agent --config config/config.yaml

# In another terminal — use --http1.1 to avoid HTTP/2 binary framing (curl / OpenSSL)
curl --http1.1 https://httpbin.org/get
curl --http1.1 https://httpbin.org/post -H 'Content-Type: application/json' -d '{"hello":"world"}'

# wget uses GnuTLS — exercises a different SSL library path
wget -q -O /dev/null https://httpbin.org/get

# node.js uses BoringSSL (statically linked)
node -e "require('https').get('https://httpbin.org/get', r => r.resume())"
```

### Example output

**curl (OpenSSL / `libssl.so`)**
```json
{"timestamp":"2026-02-22T14:58:39.270923093Z","src_ip":"","dst_ip":"","src_port":0,"dst_port":0,"protocol":"TLS","direction":"egress","pid":349147,"process_name":"curl","http_method":"POST","url":"/post","request_headers":{"Accept":"*/*","Content-Length":"17","Content-Type":"application/json","Host":"httpbin.org","User-Agent":"curl/7.81.0"},"body_snippet":"{\"hello\":\"world\"}","tls_intercepted":true}
{"timestamp":"2026-02-22T14:58:39.798016124Z","src_ip":"","dst_ip":"","src_port":0,"dst_port":0,"protocol":"TLS","direction":"ingress","pid":349147,"process_name":"curl","status_code":200,"response_headers":{"Content-Length":"434","Content-Type":"application/json","Server":"gunicorn/19.9.0"},"body_snippet":"{\n  \"data\": \"{\\\"hello\\\":\\\"world\\\"}\", ...}","tls_intercepted":true}
```

**wget (GnuTLS / `libgnutls.so`)**
```json
{"timestamp":"2026-02-23T08:12:22.443905725Z","src_ip":"","dst_ip":"","src_port":0,"dst_port":0,"protocol":"TLS","direction":"egress","pid":495490,"process_name":"wget","http_method":"GET","url":"/get","request_headers":{"Accept":"*/*","Host":"httpbin.org","User-Agent":"Wget/1.21.2"},"tls_intercepted":true}
{"timestamp":"2026-02-23T08:12:22.921146727Z","src_ip":"","dst_ip":"","src_port":0,"dst_port":0,"protocol":"TLS","direction":"ingress","pid":495490,"process_name":"wget","status_code":200,"response_headers":{"Content-Length":"293","Content-Type":"application/json"},"body_snippet":"{\n  \"url\": \"https://httpbin.org/get\"\n}\n","tls_intercepted":true}
```

**Firefox (NSS/NSPR / `libnspr4.so`) — captive portal check captured automatically on startup**
```json
{"timestamp":"2026-02-23T08:24:21.938143297Z","src_ip":"192.168.68.61","dst_ip":"34.107.221.82","src_port":32866,"dst_port":80,"protocol":"TCP","direction":"egress","pid":504879,"process_name":"firefox","http_method":"GET","url":"/canonical.html","request_headers":{"Host":"detectportal.firefox.com","User-Agent":"Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0"},"tls_intercepted":false}
{"timestamp":"2026-02-23T08:25:42.484974858Z","src_ip":"","dst_ip":"","src_port":0,"dst_port":0,"protocol":"TLS","direction":"egress","pid":507713,"process_name":"Socket Thread","http_method":"GET","url":"/canonical.html","request_headers":{"Host":"detectportal.firefox.com","User-Agent":"Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0"},"tls_intercepted":true}
```

> **Note on Firefox process names:** Firefox's network I/O runs on a dedicated thread whose Linux comm is `"Socket Thread"`. This appears as `process_name` on TLS events. Plain HTTP events from the same Firefox instance show `"firefox"` as the process_name (resolved from `/proc/net/tcp`).

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

### BoringSSL — statically linked executables

Some applications (e.g., Chromium, some gRPC builds) bundle BoringSSL as a **static library** inside the binary rather than a shared `.so`. The agent handles three cases automatically:

| Case | Detection | Action |
|------|-----------|--------|
| BoringSSL as a `.so` | Found in `/proc/<pid>/maps` | Attaches by symbol name like any other SSL library |
| Static BoringSSL with ELF symbols | Scans `.symtab`/`.dynsym` of the executable | Attaches by symbol name to the executable |
| Static BoringSSL, fully stripped | No symbols present | Requires explicit file offsets in config |

For **stripped binaries** (e.g., a production Chromium snap), find the offsets from a debug build of the same version and specify them in config:

```yaml
tls:
  enabled: true
  boringssl_executables:
    - path: /snap/chromium/current/usr/lib/chromium-browser/chromium
      process_name: chrome
      ssl_write_offset: 0x1234abc0   # file offset of SSL_write in the binary
      ssl_read_offset:  0x1234def0   # file offset of SSL_read in the binary
```

To find the offsets from a symbol-bearing build:

```bash
# From a debug build or non-stripped binary:
readelf -sW /path/to/chromium | grep -E 'SSL_write|SSL_read'
# Note the Value (virtual address), then subtract the load address from /proc/<pid>/maps
```

### Go TLS limitation

Go programs use the built-in `crypto/tls` package, which does **not** link against OpenSSL or any of the above libraries. SSL uprobes do not cover Go HTTPS clients or servers. See [Known Limitations](#known-limitations).

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
# Hooks into SSL library write/read functions to capture plaintext
# before encryption and after decryption — no certificate injection.
# Automatically detects OpenSSL, BoringSSL, GnuTLS, and NSS/NSPR
# by scanning /proc/*/maps at startup. No per-library configuration needed.
# -----------------------------------------------------------------------

tls:
  # Enable SSL uprobe interception.
  # Default: true
  enabled: true

  # Attach uprobes only to these process IDs.
  # If empty (and enabled: true), attaches globally to all processes
  # that use any known SSL library (OpenSSL, BoringSSL, GnuTLS, NSS/NSPR).
  # Default: [] (all processes)
  # pids:
  #   - 1234

  # Attach uprobes only to processes with these names.
  # Default: [] (all processes)
  # processes:
  #   - nginx
  #   - envoy

  # Static BoringSSL executables (for applications that bundle BoringSSL
  # as a static library rather than a shared .so).
  #
  # Three attachment modes (tried automatically in order):
  #   1. BoringSSL shipped as a .so — found via /proc/maps, no config needed
  #   2. Static BoringSSL with ELF symbols — executable scanned at startup
  #   3. Static BoringSSL, fully stripped — requires ssl_write_offset / ssl_read_offset below
  #
  # Only needed for case 3 (stripped production binaries such as Chromium snap).
  # Default: [] (disabled)
  # boringssl_executables:
  #   - path: /snap/chromium/current/usr/lib/chromium-browser/chromium
  #     process_name: chrome   # used only for log messages
  #     ssl_write_offset: 0x0  # file offset of SSL_write; find from a debug build
  #     ssl_read_offset:  0x0  # file offset of SSL_read


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
  "pid": 12345,
  "process_name": "curl",
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
  "pid": 12345,
  "process_name": "curl",
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
| `pid` | number | Process ID of the owning process — populated for all events; resolved via `/proc/net/tcp` for TC events and directly from the SSL uprobe for TLS events; omitted when not resolvable |
| `process_name` | string | Process comm name (max 15 chars) — populated for all events alongside `pid`; omitted when not resolvable |
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

6. **Go TLS not intercepted** — Go's `crypto/tls` does not link against OpenSSL or any of the other supported SSL libraries, so SSL uprobes do not cover Go HTTPS clients or servers. A separate uretprobe on `crypto/tls.(*Conn).Read/Write` is planned.

7. **Stripped static BoringSSL** — Applications that statically link a stripped BoringSSL (e.g., production Chromium snap builds) have no ELF symbols for `SSL_write`/`SSL_read`. These require finding the exact file offsets from a matching debug build and providing them via `tls.boringssl_executables` in config. There is no automatic way to locate the functions in a fully stripped binary.

8. **Per-interface attachment** — TC hooks attach to one interface. Capture on multiple interfaces requires running multiple instances with different configs, or extending the code to iterate over interfaces.

9. **Container traffic** — The TC hook captures at the host interface level. Traffic between containers on a Docker bridge network is visible at the `docker0` interface, not `eth0`. Set `interface: docker0` (or the relevant veth) to capture container traffic.

10. **Kernel version** — Developed and tested on Linux 5.15 (ARM64). CO-RE requires kernel 5.8+ with `CONFIG_DEBUG_INFO_BTF=y`.
