
---

**Prompt for Claude Code:**

---

I want to build a Go-based network traffic interception agent that runs as a systemd service on Ubuntu. It must capture packets using **eBPF** (not a proxy-based approach). Below are the full requirements:

---

## Project Overview

Build a production-ready Go application called `traffic-agent` that intercepts and inspects HTTP and HTTPS (TLS) network traffic at the kernel level using eBPF, without acting as a proxy or requiring any changes to client applications.

---

## Functional Requirements

1. **Packet Capture via eBPF**
   - Use eBPF programs (via `cilium/ebpf` Go library) to attach to network interfaces using TC (Traffic Control) or XDP hooks
   - Capture both ingress and egress packets on a configurable network interface (e.g., `eth0`)
   - Extract raw packet data including Ethernet, IP, TCP headers and payload

2. **HTTP Traffic Parsing**
   - Detect and parse HTTP/1.1 request and response traffic from raw packet payloads
   - Extract: method, URL, headers, status code, response body (if available)
   - Handle TCP stream reassembly for multi-packet HTTP messages using `google/gopacket`

3. **HTTPS / TLS Traffic**
   - Use eBPF uprobes to hook into OpenSSL / GnuTLS / Go's `crypto/tls` library functions at userspace level (specifically `SSL_read` and `SSL_write`) to capture plaintext before encryption / after decryption
   - This avoids MITM and does not require certificate injection
   - Support attaching uprobes dynamically to running processes by PID or process name

4. **Traffic Filtering**
   - Allow filtering by: source/destination IP, port, process name, or PID
   - Support BPF filter expressions for fine-grained control
   - Configurable via a YAML config file at `/etc/traffic-agent/config.yaml`

5. **Output / Logging**
   - Log captured traffic to structured JSON (stdout and/or file)
   - Each log entry should include: timestamp, src_ip, dst_ip, src_port, dst_port, protocol, http_method, url, status_code, request_headers, response_headers, body_snippet (first 512 bytes), pid, process_name
   - Support log rotation (via `lumberjack`)

6. **Event Streaming (Optional but preferred)**
   - Expose a local Unix socket or HTTP endpoint (e.g., `localhost:8080/events`) to stream captured traffic events as newline-delimited JSON for downstream consumers

---

## Non-Functional Requirements

- **Language:** Go 1.22+
- **eBPF library:** `github.com/cilium/ebpf` (preferred) — include both the Go userspace code and the C eBPF kernel programs (`.c` files compiled with `clang`)
- **Packet parsing:** `github.com/google/gopacket` for TCP reassembly and protocol parsing
- **No proxy:** Do not use any MITM proxy, `iptables REDIRECT`, or `SO_REUSEPORT` tricks — all capture must be done passively via eBPF hooks
- **Privileges:** The agent must run with `CAP_BPF`, `CAP_NET_ADMIN`, and `CAP_SYS_ADMIN` capabilities (document this in the README)
- **Kernel requirement:** Linux kernel 5.8+ (for BTF and CO-RE support)

---

## Project Structure

```
traffic-agent/
├── cmd/
│   └── agent/
│       └── main.go
├── internal/
│   ├── capture/         # eBPF loader, TC/XDP attach logic
│   ├── tls/             # uprobe-based SSL interception
│   ├── parser/          # HTTP/TCP stream reassembly
│   ├── filter/          # Traffic filtering logic
│   ├── output/          # JSON logging, event streaming
│   └── config/          # YAML config loading
├── bpf/
│   ├── tc_capture.c     # eBPF TC program for packet capture
│   ├── ssl_uprobe.c     # eBPF uprobe for SSL_read/SSL_write
│   └── headers/         # vmlinux.h and common BPF headers
├── config/
│   └── config.yaml      # Default config
├── deploy/
│   └── traffic-agent.service  # systemd unit file
├── Makefile             # Targets: build, generate, lint, install
├── go.mod
└── README.md
```

---

## Systemd Service Requirements

Create a `traffic-agent.service` unit file that:
- Runs the binary as root (or with specific Linux capabilities)
- Restarts automatically on failure (`Restart=on-failure`)
- Loads config from `/etc/traffic-agent/config.yaml`
- Logs to journald

---

## Build & Toolchain

- Provide a `Makefile` with targets: `generate` (runs `go generate` for eBPF object compilation using `bpf2go`), `build`, `install`, `lint`
- Use `//go:generate` directives with `cilium/ebpf`'s `bpf2go` tool to compile `.c` eBPF programs into Go-embedded objects
- Document all build dependencies: `clang`, `llvm`, `libbpf-dev`, `linux-headers`

---

## README Requirements

Include a README with:
- Architecture overview (eBPF hook types used and why)
- Build prerequisites and steps
- Installation and configuration guide
- Required Linux capabilities and how to grant them
- Example config YAML with all options documented
- Known limitations (e.g., eBPF map size, kernel version requirements)

---

## Constraints & Notes

- Do not use `libpcap` or `AF_PACKET` sockets — eBPF only
- The SSL uprobe approach should work for OpenSSL-linked binaries; document limitations for Go TLS (which doesn't use OpenSSL)
- For Go TLS interception, hook into `crypto/tls` using uretprobes on `(*Conn).Read` and `(*Conn).Write`
- Prioritize correctness and clean code over feature completeness — if something is complex (e.g., full HTTP/2 support), stub it out with a clear TODO

---

Start by creating the full project scaffold, then implement the core eBPF capture pipeline first (`bpf/tc_capture.c` → `internal/capture/`) before moving to SSL uprobes and HTTP parsing.

---

This prompt gives Claude Code enough context to make architecture decisions, choose the right libraries, and build incrementally without asking too many follow-up questions. You can optionally append **"Ask me before making any assumptions on kernel version or network interface defaults"** if you want more control during the build.