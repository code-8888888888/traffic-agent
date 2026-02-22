// Package capture loads the compiled eBPF TC programs and attaches them to
// a network interface's ingress and egress TC hooks.
package capture

// Compile eBPF C programs into Go-embedded objects using bpf2go.
//
// Prerequisites:
//   clang >= 14, llvm, libbpf-dev, linux-headers-$(uname -r)
//
// Usage:
//   go generate ./internal/capture/
//
// This produces:
//   tc_capture_bpfeb.go  (big-endian)
//   tc_capture_bpfel.go  (little-endian)
//
// The generated files embed the compiled .o bytes and expose:
//   loadTCCapture()          → tcCaptureObjects
//   tcCaptureObjects.Programs.TcIngress  (*ebpf.Program)
//   tcCaptureObjects.Programs.TcEgress   (*ebpf.Program)
//   tcCaptureObjects.Maps.Events         (*ebpf.Map)
//   tcCaptureObjects.Maps.FilterConfigMap (*ebpf.Map)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_arm64 -mcpu=v3" TCCapture ../../bpf/tc_capture.c -- -I../../bpf/headers
