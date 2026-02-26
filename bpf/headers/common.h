/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

/*
 * common.h - Shared BPF header for traffic-agent eBPF programs
 *
 * vmlinux.h must be generated via:
 *   bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/headers/vmlinux.h
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

/* Ethernet */
#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define ETH_HLEN    14

/* IP protocols */
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/* TC actions */
#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

/* Max sizes — must be a power of 2 to enable the verifier-required mask trick
 * (copy_len &= MAX_PAYLOAD_SIZE - 1).
 *
 * 16384 is large enough to handle GRO-coalesced UDP datagrams (the kernel's
 * generic-receive-offload merges multiple QUIC datagrams into one large skb
 * before the TC ingress hook). Typical GRO batches are 3-8 datagrams at
 * ~1400 bytes each = ~4200-11200 bytes. */
#define MAX_PAYLOAD_SIZE 16384
/* MAX_SSL_DATA_SIZE: bytes copied per SSL_write/SSL_read uretprobe call.
 * Must be large enough to capture a complete HTTP/1.1 request header block
 * plus POST body in a single SSL_write.  16 KiB matches the default HTTP/2
 * SETTINGS_MAX_FRAME_SIZE and captures most POST payloads in full.
 * bpf_probe_read_user runs in the application's thread context; 16 KiB
 * copies are still under 5 µs on modern ARM64 cores. */
#define MAX_SSL_DATA_SIZE 16384
#define TASK_COMM_LEN 16

/* Direction flags */
#define DIR_INGRESS 0
#define DIR_EGRESS  1

/*
 * barrier_var(var) — prevent the compiler from CSE-ing or dead-code-
 * eliminating code that depends on var.  The empty inline asm declares var
 * as both an input ("0") and output ("=r"), so the compiler must treat the
 * value as potentially modified and cannot assume any previously computed
 * range still holds.  This is a no-op at runtime.
 *
 * Use before a zero-check that the compiler would otherwise merge with a
 * downstream error-path that produces the same net effect.
 */
#ifndef barrier_var
# define barrier_var(var) asm volatile("" : "=r"(var) : "0"(var))
#endif
