// Package tls manages eBPF uprobes for intercepting plaintext TLS traffic
// by hooking into OpenSSL's SSL_read and SSL_write functions.
package tls

// Compile the SSL uprobe BPF program:
//
//	go generate ./internal/tls/
//
// Generated files:
//   ssl_uprobe_bpfeb.go (big-endian)
//   ssl_uprobe_bpfel.go (little-endian)
//
// Exposed types:
//   loadSSLUprobe()           → sslUprobeObjects
//   sslUprobeObjects.Programs.UprobeSSLWrite    (*ebpf.Program)
//   sslUprobeObjects.Programs.UretprobeSSLWrite (*ebpf.Program)
//   sslUprobeObjects.Programs.UprobeSSLRead     (*ebpf.Program)
//   sslUprobeObjects.Programs.UretprobeSSLRead  (*ebpf.Program)
//   sslUprobeObjects.Maps.SslEvents             (*ebpf.Map)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_arm64" SSLUprobe ../../bpf/ssl_uprobe.c -- -I../../bpf/headers
