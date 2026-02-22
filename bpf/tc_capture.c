// SPDX-License-Identifier: GPL-2.0
/*
 * tc_capture.c - eBPF TC (Traffic Control) program for passive packet capture
 *
 * Attached to both ingress and egress hooks on a network interface via the
 * Linux TC subsystem. Extracts TCP packet metadata and payload for HTTP/HTTPS
 * traffic and forwards events to userspace via a BPF ring buffer.
 *
 * Compile via bpf2go (see internal/capture/gen.go):
 *   go generate ./internal/capture/
 */

#include "headers/common.h"

char __license[] SEC("license") = "GPL";

/* -----------------------------------------------------------------------
 * BPF Maps
 * --------------------------------------------------------------------- */

/**
 * events - Ring buffer for sending packet events to userspace.
 * Size: 256 KiB (must be a power of two multiple of PAGE_SIZE).
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/**
 * filter_config - Single-entry array holding runtime filter settings.
 * Updated by userspace to configure per-IP/port filtering.
 */
struct filter_config {
    __u32 src_ip;       /* 0 = match any */
    __u32 dst_ip;       /* 0 = match any */
    __u16 src_port;     /* 0 = match any */
    __u16 dst_port;     /* 0 = match any */
    __u32 flags;        /* reserved */
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct filter_config);
} filter_config_map SEC(".maps");

/* -----------------------------------------------------------------------
 * Event structure sent to userspace
 * --------------------------------------------------------------------- */

struct packet_event {
    __u64 timestamp_ns;         /* bpf_ktime_get_ns() */
    __u32 src_ip;               /* network byte order */
    __u32 dst_ip;               /* network byte order */
    __u16 src_port;             /* host byte order */
    __u16 dst_port;             /* host byte order */
    __u8  direction;            /* DIR_INGRESS / DIR_EGRESS */
    __u8  protocol;             /* IPPROTO_TCP etc. */
    __u8  tcp_flags;            /* SYN/ACK/FIN/RST */
    __u8  _pad;
    __u32 payload_len;          /* actual bytes copied */
    __u8  payload[MAX_PAYLOAD_SIZE];
};

/* -----------------------------------------------------------------------
 * Helpers
 * --------------------------------------------------------------------- */

static __always_inline int should_capture(__u16 dst_port, __u16 src_port)
{
    /* Capture HTTP (80), HTTPS (443), and common alternate ports.
     * TODO: make this configurable via filter_config_map */
    return (dst_port == 80  || src_port == 80  ||
            dst_port == 443 || src_port == 443 ||
            dst_port == 8080 || src_port == 8080 ||
            dst_port == 8443 || src_port == 8443);
}

/* -----------------------------------------------------------------------
 * Core packet processing
 * --------------------------------------------------------------------- */

static __always_inline int process_packet(struct __sk_buff *skb, __u8 direction)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* --- Ethernet --- */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    /* --- IPv4 --- */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    /* --- TCP --- */
    /* Explicitly bound ihl and doff so the verifier can track payload_off range.
     * RFC 791: IHL is 4 bits, valid range 5-15 (20-60 bytes).
     * RFC 793: Data Offset is 4 bits, valid range 5-15 (20-60 bytes). */
    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20 || ip_hdr_len > 60)
        return TC_ACT_OK;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    __u16 src_port = bpf_ntohs(tcp->source);
    __u16 dst_port = bpf_ntohs(tcp->dest);

    if (!should_capture(dst_port, src_port))
        return TC_ACT_OK;

    __u32 tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < 20 || tcp_hdr_len > 60)
        return TC_ACT_OK;

    /* Payload offset is bounded [54, 134] from the ihl/doff bounds above.
     * NOTE: we intentionally do NOT check (payload_off >= skb->len) here.
     * Doing so would cause the compiler to compute (skb->len - payload_off)
     * at that early branch, spill it to the stack, and later reload the
     * pre-mask value for bpf_skb_load_bytes — giving the verifier
     * smin=-134 and triggering "R4 min value is negative".
     * Instead we defer the check to right before bpf_skb_load_bytes. */
    __u32 payload_off = ETH_HLEN + ip_hdr_len + tcp_hdr_len;

    /* --- Apply filter config --- */
    __u32 zero = 0;
    struct filter_config *cfg = bpf_map_lookup_elem(&filter_config_map, &zero);
    if (cfg && cfg->flags != 0) {
        if (cfg->src_ip   && cfg->src_ip   != ip->saddr)  return TC_ACT_OK;
        if (cfg->dst_ip   && cfg->dst_ip   != ip->daddr)  return TC_ACT_OK;
        if (cfg->src_port && cfg->src_port != src_port)    return TC_ACT_OK;
        if (cfg->dst_port && cfg->dst_port != dst_port)    return TC_ACT_OK;
    }

    /* --- Allocate ring buffer slot --- */
    struct packet_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return TC_ACT_OK;

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->src_ip       = ip->saddr;
    ev->dst_ip       = ip->daddr;
    ev->src_port     = src_port;
    ev->dst_port     = dst_port;
    ev->direction    = direction;
    ev->protocol     = ip->protocol;
    ev->tcp_flags    = 0;
    ev->_pad         = 0;

    /* ----------------------------------------------------------------
     * Payload length calculation — verifier-safe for kernel 5.15
     * ----------------------------------------------------------------
     * bpf_skb_load_bytes uses ARG_CONST_SIZE, requiring len.umin >= 1.
     *
     * Previous attempts failed:
     * - Mask trick: umax=2047, umin=0; "!= 0" emits JNE which does NOT
     *   update umin in kernel 5.15.
     * - "(int)raw_len <= 0": clang generates shift-based sign-extension
     *   (r1=r4; r1<<=32; r2=r1; r2 s>>=32; JSGT r2, 0).  The JSGT
     *   constraint lands on r2 (the sign-extended copy), NOT on r4
     *   (the original register passed to bpf_skb_load_bytes).  The
     *   verifier tracks them independently → r4.umin stays 0.
     *
     * Fix: "tmp = raw_len - 1" unsigned-wrap trick.
     *
     * 1. tmp = raw_len - 1  →  wraps to UINT32_MAX when raw_len == 0.
     * 2. "if (tmp > (MAX_PAYLOAD_SIZE-2))" emits unsigned JGT on tmp
     *    directly (opcode 0x25).  Catches both:
     *      raw_len == 0   → tmp = UINT32_MAX > 2046 → taken (discard)
     *      raw_len > 2047 → tmp > 2046              → taken (clamp)
     * 3. JGT NOT-taken path: tmp.umax = MAX_PAYLOAD_SIZE-2 = 2046.
     * 4. payload_len = tmp + 1:
     *      umin = tmp.umin + 1 = 0 + 1 = 1  ✓
     *      umax = tmp.umax + 1 = 2046 + 1 = 2047  ✓
     *
     * In the JGT taken path:
     *   raw_len == 0   → discard and return (no PHI contribution)
     *   raw_len > 2047 → tmp = 2046 (constant) → payload_len = 2047
     *
     * PHI merge: both surviving contributors have tmp.umax = 2046,
     * so bpf_skb_load_bytes receives payload_len with umin = 1. */
    __u32 raw_len = skb->len - payload_off;
    __u32 tmp     = raw_len - 1;  /* wraps to UINT32_MAX if raw_len == 0 */

    if (tmp > (MAX_PAYLOAD_SIZE - 2)) {
        /* raw_len == 0 (empty payload: ACK/SYN/FIN) or
         * raw_len > MAX_PAYLOAD_SIZE-1 (large payload, needs clamping). */
        if (raw_len == 0) {
            bpf_ringbuf_discard(ev, 0);
            return TC_ACT_OK;
        }
        /* Large payload: clamp tmp → payload_len = MAX_PAYLOAD_SIZE-1. */
        tmp = MAX_PAYLOAD_SIZE - 2;
    }

    /* tmp ∈ [0, MAX_PAYLOAD_SIZE-2] from both surviving paths.
     * Verifier: tmp.umax = 2046 → payload_len = tmp+1: umin=1, umax=2047. */
    __u32 payload_len = tmp + 1;

    ev->payload_len = payload_len;
    {
        long err = bpf_skb_load_bytes(skb, payload_off, ev->payload,
                                      payload_len);
        if (err < 0) {
            bpf_ringbuf_discard(ev, 0);
            return TC_ACT_OK;
        }
    }
    bpf_ringbuf_submit(ev, 0);
    return TC_ACT_OK;
}

/* -----------------------------------------------------------------------
 * TC entry points
 * --------------------------------------------------------------------- */

SEC("tc/ingress")
int tc_ingress(struct __sk_buff *skb)
{
    return process_packet(skb, DIR_INGRESS);
}

SEC("tc/egress")
int tc_egress(struct __sk_buff *skb)
{
    return process_packet(skb, DIR_EGRESS);
}
