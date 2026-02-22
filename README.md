# traffic-agent

A production-ready Go application that intercepts and inspects HTTP and HTTPS (TLS) network traffic at the kernel level using **eBPF**, without acting as a proxy or requiring changes to client applications.

---

## Architecture Overview

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
                  │  │          HTTP Parser (parser/)        │    │
                  │  │     gopacket TCP reassembly +         │    │
                  │  │     net/http request/response parse   │    │
                  │  └─────────────────────┬─────────────────┘   │
                  │                        │ TrafficEvent         │
                  │              ┌─────────▼──────────┐          │
                  │              │    Filter (filter/) │          │
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

### eBPF Hook Types Used

| Hook | Purpose | Why |
|------|---------|-----|
| **TC ingress** | Capture inbound TCP payload | Runs after NIC driver, before socket; sees all traffic including traffic not yet accepted |
| **TC egress** | Capture outbound TCP payload | Runs before packet leaves the host; sees plaintext before kernel's TLS-offload (if any) |
| **uprobe/SSL_write** + **uretprobe/SSL_write** | Save plaintext buf pointer on entry; capture after write returns | SSL_write data is plaintext *before* OpenSSL encrypts it |
| **uprobe/SSL_read** + **uretprobe/SSL_read** | Save buf pointer; read plaintext on return | Buffer is populated *after* OpenSSL decrypts; must capture on uretprobe |

---

## Build Prerequisites

### System packages

```bash
# Ubuntu / Debian
sudo apt-get install -y \
    clang llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    linux-tools-$(uname -r)   # provides bpftool

# Verify kernel BTF support (required)
ls /sys/kernel/btf/vmlinux
```

### Go toolchain

```bash
# Go 1.22+
go version

# bpf2go (installed automatically via go generate)
go install github.com/cilium/ebpf/cmd/bpf2go@latest
```

### Kernel requirements

- **Linux 5.8+** with `CONFIG_DEBUG_INFO_BTF=y` (for CO-RE support)
- **Linux 5.11+** recommended (removes `RLIMIT_MEMLOCK` requirement for eBPF maps)
- Verify: `uname -r && cat /boot/config-$(uname -r) | grep CONFIG_DEBUG_INFO_BTF`

---

## Build Steps

```bash
# 1. Clone the repository
git clone https://github.com/traffic-agent/traffic-agent
cd traffic-agent

# 2. Generate vmlinux.h from the running kernel (one-time)
make vmlinux

# 3. Run go mod tidy to fetch dependencies
make tidy

# 4. Compile eBPF C programs and build the binary
make build

# Output: ./bin/traffic-agent
```

---

## Installation

```bash
# Install binary, config, and systemd service
sudo make install

# Enable and start the service
sudo systemctl enable --now traffic-agent

# View logs
sudo journalctl -u traffic-agent -f
```

---

## Configuration

The default config is installed to `/etc/traffic-agent/config.yaml`.

```yaml
# Network interface to monitor
interface: eth0

# TCP ports to capture
ports: [80, 443, 8080, 8443]

filter:
  # Filter by source/destination IP
  # src_ips: ["10.0.0.1"]
  # dst_ips: ["93.184.216.34"]

  # Filter by process name
  # processes: ["curl", "nginx"]

output:
  stdout: true
  file: /var/log/traffic-agent/events.json
  max_size_mb: 100
  max_age_days: 7
  max_backups: 3
  compress: true

tls:
  enabled: false          # set true to enable SSL uprobe interception
  # processes: ["nginx"]

event_stream:
  enabled: false          # set true to expose HTTP event stream
  address: "127.0.0.1:8080"
  path: /events
```

### Stream events over HTTP

```bash
# Enable event_stream in config, then:
curl -N http://127.0.0.1:8080/events
```

---

## Required Linux Capabilities

The agent must run with:

| Capability | Why |
|-----------|-----|
| `CAP_BPF` | Load and manage eBPF programs and maps |
| `CAP_NET_ADMIN` | Attach TC filters to network interfaces |
| `CAP_SYS_ADMIN` | Required for certain eBPF operations on kernels < 5.8 |
| `CAP_SYS_PTRACE` | Read `/proc/<pid>/maps` for SSL uprobe symbol resolution |

### Granting capabilities to the binary (non-root)

```bash
# Create a dedicated user
useradd -r -s /sbin/nologin traffic-agent

# Grant capabilities to the binary
setcap 'cap_bpf,cap_net_admin,cap_sys_admin,cap_sys_ptrace+eip' \
    /usr/local/bin/traffic-agent
```

Update `deploy/traffic-agent.service` to use `User=traffic-agent` with `AmbientCapabilities` (see commented section in the unit file).

---

## Example Output (JSON)

```json
{
  "timestamp": "2026-02-21T10:15:30.123456Z",
  "src_ip": "10.0.1.42",
  "dst_ip": "93.184.216.34",
  "src_port": 54321,
  "dst_port": 80,
  "protocol": "TCP",
  "direction": "egress",
  "pid": 12345,
  "process_name": "curl",
  "http_method": "GET",
  "url": "/index.html",
  "status_code": 0,
  "request_headers": {
    "Host": "example.com",
    "User-Agent": "curl/8.5.0",
    "Accept": "*/*"
  },
  "body_snippet": ""
}
```

---

## Known Limitations

1. **eBPF map sizes** — The ring buffer is 256 KiB for TC events and 512 KiB for SSL events. Under high traffic load, events may be dropped. Increase `max_entries` in the BPF map definitions and recompile.

2. **TCP reassembly** — The TC capture passes individual packets; gopacket's reassembler handles reordering but requires buffering. Long-lived HTTP/1.1 keep-alive streams with many requests may consume memory.

3. **HTTP/2 not supported** — HTTP/2 uses binary framing (HPACK). Parsing is stubbed out. HTTPS/2 captured via SSL uprobes contains raw TLS record data that would need an additional HTTP/2 framing parser.

4. **Go TLS interception** — Go's standard library (`crypto/tls`) does not link against OpenSSL. The SSL uprobes do **not** intercept Go HTTPS clients/servers. A separate set of uretprobes on `crypto/tls.(*Conn).Read` / `Write` is planned (see TODO in `bpf/ssl_uprobe.c`).

5. **Container/namespace support** — The TC hook attaches to the host network interface. Traffic inside containers using network namespaces (e.g. Docker bridge) will be captured at the veth level. Attaching to individual container veth pairs requires additional logic.

6. **Kernel version** — Tested on Linux 5.15+. CO-RE requires kernel 5.8+ with BTF. The stub `vmlinux.h` allows compilation but the eBPF verifier may reject programs if the real BTF types differ significantly.

7. **IPv6** — Currently only IPv4 is parsed in the TC program. IPv6 support is straightforward to add by checking `ETH_P_IPV6` and parsing `ip6hdr`.

---

## Development

```bash
# Run linter
make lint

# Run tests
make test

# Clean generated files
make clean

# Regenerate everything from scratch
make vmlinux && make generate && make build
```

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
