// SPDX-License-Identifier: GPL-2.0
/*
 * ssl_uprobe.c - eBPF uprobes for OpenSSL SSL_read / SSL_write interception
 *
 * Hooks into the OpenSSL library functions at the userspace level so that
 * plaintext is captured *before* encryption (SSL_write) and *after*
 * decryption (SSL_read). This is entirely passive and requires no MITM or
 * certificate injection.
 *
 * Supported targets:
 *   - OpenSSL:  SSL_read, SSL_write  (libssl.so)
 *   - GnuTLS:   gnutls_record_send, gnutls_record_recv (TODO)
 *   - Go TLS:   crypto/tls.(*Conn).Read/Write via uretprobes (see below)
 *
 * Attach points are discovered at runtime by scanning the target process's
 * /proc/<pid>/maps for libssl.so and computing symbol offsets.
 *
 * Compile via bpf2go (see internal/tls/gen.go).
 */

#include "headers/common.h"

char __license[] SEC("license") = "GPL";

/* -----------------------------------------------------------------------
 * BPF Maps
 * --------------------------------------------------------------------- */

/**
 * ssl_events - Ring buffer for plaintext SSL data sent to userspace.
 * 64 MiB: NSPR's PR_Write fires for ALL I/O (IPC, files, TLS), so
 * browsers generate many events per second.  With MAX_SSL_DATA_SIZE=16384
 * each event is ~16 KiB, giving room for ~4000 events.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);
} ssl_events SEC(".maps");

/**
 * active_ssl_read_args / active_ssl_write_args
 * Stash the buffer pointer and size from the uprobe entry so the
 * uretprobe can read the data after the return value is known.
 * Keyed by thread ID (lower 32 bits of pid_tgid).
 */
struct ssl_args {
    __u64 buf;       /* pointer to plaintext buffer (user address) */
    __u64 conn_id;   /* SSL/PRFileDesc pointer — opaque per-connection key */
    __u32 num;       /* requested length */
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct ssl_args);
} active_ssl_read_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct ssl_args);
} active_ssl_write_args SEC(".maps");

/* -----------------------------------------------------------------------
 * Event structure
 * --------------------------------------------------------------------- */

struct ssl_event {
    __u64 timestamp_ns;
    __u64 conn_id;              /* SSL/PRFileDesc pointer — opaque per-connection key */
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u8  is_read;              /* 1 = SSL_read, 0 = SSL_write */
    __u8  _pad[3];
    __u32 data_len;
    __u8  comm[TASK_COMM_LEN];
    __u8  data[MAX_SSL_DATA_SIZE];
};

/* -----------------------------------------------------------------------
 * SSL_write uprobe / uretprobe
 *
 * Signature: int SSL_write(SSL *ssl, const void *buf, int num)
 *   arg1 = ssl  (ignored)
 *   arg2 = buf  (plaintext to send)
 *   arg3 = num  (byte count requested)
 *   ret  = bytes actually written, or <=0 on error
 * --------------------------------------------------------------------- */

SEC("uprobe/SSL_write")
int uprobe_ssl_write_entry(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    struct ssl_args args = {
        .buf = PT_REGS_PARM2(ctx),
        .conn_id = PT_REGS_PARM1(ctx),
        .num = (__u32)PT_REGS_PARM3(ctx),
    };
    bpf_map_update_elem(&active_ssl_write_args, &tid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_write")
int uretprobe_ssl_write_ret(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    struct ssl_args *args = bpf_map_lookup_elem(&active_ssl_write_args, &tid);
    if (!args)
        return 0;

    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0)
        goto cleanup;

    struct ssl_event *ev = bpf_ringbuf_reserve(&ssl_events, sizeof(*ev), 0);
    if (!ev)
        goto cleanup;

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->conn_id      = args->conn_id;
    ev->pid          = ((__u64)bpf_get_current_pid_tgid()) >> 32;
    ev->tid          = tid;
    ev->uid          = (__u32)bpf_get_current_uid_gid();
    ev->is_read      = 0;
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    __u32 data_len = (__u32)ret;
    if (data_len > MAX_SSL_DATA_SIZE)
        data_len = MAX_SSL_DATA_SIZE;
    ev->data_len = data_len;

    if (bpf_probe_read_user(ev->data, data_len, (void *)args->buf) < 0) {
        bpf_ringbuf_discard(ev, 0);
        goto cleanup;
    }

    bpf_ringbuf_submit(ev, 0);

cleanup:
    bpf_map_delete_elem(&active_ssl_write_args, &tid);
    return 0;
}

/* -----------------------------------------------------------------------
 * SSL_read uprobe / uretprobe
 *
 * Signature: int SSL_read(SSL *ssl, void *buf, int num)
 *   arg1 = ssl  (ignored)
 *   arg2 = buf  (buffer to receive plaintext)
 *   arg3 = num  (byte count requested)
 *   ret  = bytes actually read, or <=0 on error/EOF
 *
 * The buffer is only valid *after* SSL_read returns successfully, so we
 * capture it in the uretprobe.
 * --------------------------------------------------------------------- */

SEC("uprobe/SSL_read")
int uprobe_ssl_read_entry(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    struct ssl_args args = {
        .buf = PT_REGS_PARM2(ctx),
        .conn_id = PT_REGS_PARM1(ctx),
        .num = (__u32)PT_REGS_PARM3(ctx),
    };
    bpf_map_update_elem(&active_ssl_read_args, &tid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int uretprobe_ssl_read_ret(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    struct ssl_args *args = bpf_map_lookup_elem(&active_ssl_read_args, &tid);
    if (!args)
        return 0;

    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0)
        goto cleanup;

    struct ssl_event *ev = bpf_ringbuf_reserve(&ssl_events, sizeof(*ev), 0);
    if (!ev)
        goto cleanup;

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->conn_id      = args->conn_id;
    ev->pid          = ((__u64)bpf_get_current_pid_tgid()) >> 32;
    ev->tid          = tid;
    ev->uid          = (__u32)bpf_get_current_uid_gid();
    ev->is_read      = 1;
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    __u32 data_len = (__u32)ret;
    if (data_len > MAX_SSL_DATA_SIZE)
        data_len = MAX_SSL_DATA_SIZE;
    ev->data_len = data_len;

    if (bpf_probe_read_user(ev->data, data_len, (void *)args->buf) < 0) {
        bpf_ringbuf_discard(ev, 0);
        goto cleanup;
    }

    bpf_ringbuf_submit(ev, 0);

cleanup:
    bpf_map_delete_elem(&active_ssl_read_args, &tid);
    return 0;
}

/* -----------------------------------------------------------------------
 * NSPR PRFileDesc layered I/O — ConnID resolution
 *
 * NSPR uses a layered I/O model: PRFileDesc structs are stacked via
 * the `lower` and `higher` pointers.  For Firefox HTTPS connections:
 *
 *   [Top-level PRFileDesc]  ← PR_Write/PR_Send/PR_Writev gets this (arg1)
 *        │ lower (offset 16)
 *        ▼
 *   [SSL layer PRFileDesc]  ← ssl_SecureRecv in libssl3.so gets this (arg1)
 *        │ lower (offset 16)
 *        ▼
 *   [TCP socket PRFileDesc]
 *
 * The write-side probes (PR_Write et al.) see the top-level fd, while
 * the read-side probe (ssl_SecureRecv) sees the SSL-layer fd.  These
 * are DIFFERENT pointers, so using arg1 directly as ConnID produces
 * mismatched keys — writes and reads never correlate.
 *
 * Fix: dereference fd->lower (PRFileDesc.lower at offset 16) in the
 * write-side probes to get the SSL layer's fd, which matches the read
 * side.  If the read fails or lower is NULL, fall back to using fd.
 * --------------------------------------------------------------------- */

/* Offset of the `lower` field in struct PRFileDesc (stable across NSPR
 * versions and 64-bit architectures: methods [0], secret [8], lower [16]). */
#define PRFILEDESC_LOWER_OFFSET 16

/* Maximum NSPR layer depth to walk.  Firefox typically has 2-3 layers
 * (top → SSL → TCP, or top → filter → SSL → TCP).  4 is generous. */
#define NSPR_MAX_LAYER_DEPTH 4

/**
 * nspr_resolve_conn_id — walk the PRFileDesc->lower chain to find the
 * bottom-most fd (the TCP socket layer, where lower == NULL).  This fd
 * is the same regardless of which layer the caller starts from, so both
 * write-side (top-level fd from PR_Write) and read-side (SSL-layer fd
 * from ssl_SecureRecv) converge on the same pointer.
 *
 * Manually unrolled for the BPF verifier (no loops).
 * Falls back to returning the original fd if reads fail.
 */
static __always_inline __u64 nspr_resolve_conn_id(__u64 fd)
{
    __u64 cur = fd;
    __u64 lower = 0;

    /* Level 1 */
    if (bpf_probe_read_user(&lower, sizeof(lower),
                            (void *)(cur + PRFILEDESC_LOWER_OFFSET)) != 0
        || lower == 0)
        return cur;
    cur = lower;

    /* Level 2 */
    lower = 0;
    if (bpf_probe_read_user(&lower, sizeof(lower),
                            (void *)(cur + PRFILEDESC_LOWER_OFFSET)) != 0
        || lower == 0)
        return cur;
    cur = lower;

    /* Level 3 */
    lower = 0;
    if (bpf_probe_read_user(&lower, sizeof(lower),
                            (void *)(cur + PRFILEDESC_LOWER_OFFSET)) != 0
        || lower == 0)
        return cur;
    cur = lower;

    /* Level 4 */
    lower = 0;
    if (bpf_probe_read_user(&lower, sizeof(lower),
                            (void *)(cur + PRFILEDESC_LOWER_OFFSET)) != 0
        || lower == 0)
        return cur;
    cur = lower;

    return cur;
}

/* -----------------------------------------------------------------------
 * SSL_write entry-only capture (for tail-calling write functions)
 *
 * Some SSL/TLS libraries implement their write function as an indirect
 * tail-call rather than a proper function call with a RET instruction.
 * NSS/NSPR's PR_Write is the canonical example on ARM64:
 *
 *   PR_Write(fd, buf, amount):
 *     ldr x8, [x0]        ; fd->methods
 *     ldr x3, [x8, #24]   ; methods->write (function pointer)
 *     br  x3              ; tail-call — no return frame pushed, no RET
 *
 * Because BR does not push a return address, a uretprobe registered on
 * PR_Write will never fire.  The entry uprobe DOES fire, and at that
 * point the plaintext is already present in PARM2 (x1=buf, ARM64), so
 * we read it immediately without stashing args for a uretprobe.
 *
 * Compatible calling convention (same as SSL_write):
 *   int fn(void *ctx, const void *buf, int num)
 *   arg1 (x0) = PRFileDesc *fd  — top-level layered fd
 *   arg2 (x1) = buf  — plaintext data to write
 *   arg3 (x2) = num  — byte count
 *
 * ConnID: uses fd->lower (SSL layer fd) for correlation with the
 * read-side ssl_SecureRecv probe in libssl3.so.
 * --------------------------------------------------------------------- */

SEC("uprobe/SSL_write_entry_cap")
int uprobe_ssl_write_entry_cap(struct pt_regs *ctx)
{
    void  *buf = (void *)PT_REGS_PARM2(ctx);
    __u32  num = (__u32)PT_REGS_PARM3(ctx);

    if (num == 0)
        return 0;

    /* Resolve ConnID BEFORE ringbuf reserve to avoid verifier losing
     * register bounds after the inlined bpf_probe_read_user calls. */
    __u64 conn_id = nspr_resolve_conn_id(PT_REGS_PARM1(ctx));

    struct ssl_event *ev = bpf_ringbuf_reserve(&ssl_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->conn_id      = conn_id;
    ev->pid          = ((__u64)bpf_get_current_pid_tgid()) >> 32;
    ev->tid          = (__u32)bpf_get_current_pid_tgid();
    ev->uid          = (__u32)bpf_get_current_uid_gid();
    ev->is_read      = 0;
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    __u32 data_len = num > MAX_SSL_DATA_SIZE ? MAX_SSL_DATA_SIZE : num;
    /* Re-assert bounds for the BPF verifier after heavy inlining above.
     * Use 2*MAX-1 so the full MAX_SSL_DATA_SIZE value is preserved. */
    data_len &= (2 * MAX_SSL_DATA_SIZE - 1);
    ev->data_len = data_len;

    if (bpf_probe_read_user(ev->data, data_len, buf) < 0) {
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* -----------------------------------------------------------------------
 * PR_Writev entry-only capture (scatter-gather write)
 *
 * NSPR's PR_Writev is a scatter-gather variant of PR_Write.  Firefox's
 * HTTP/2 engine uses it to send multiple H2 frames in a single call.
 * Like PR_Write, it is a 3-instruction indirect tail-call on ARM64:
 *
 *   PR_Writev(fd, iov, iov_size, timeout):
 *     ldr x8, [x0]          ; fd->methods
 *     ldr x4, [x8, #88]     ; methods->writev
 *     br  x4                 ; tail-call
 *
 * Calling convention (ARM64):
 *   arg1 (x0) = PRFileDesc *fd   — top-level layered fd
 *   arg2 (x1) = PRIOVec *iov     — array of {void *iov_base; PRInt32 iov_len}
 *   arg3 (x2) = PRInt32 iov_size — number of entries
 *   arg4 (x3) = PRIntervalTime   — timeout (ignored)
 *
 * PRIOVec layout on 64-bit: { char *iov_base (8 bytes), int iov_len (4 bytes),
 *   4 bytes padding } = 16 bytes per entry.
 *
 * Emits one ssl_event per non-empty iov entry for simplicity.  The
 * userspace parser accumulates per-ConnID, so fragmented H2 frames
 * across iov entries are reassembled correctly.
 *
 * ConnID: uses fd->lower (SSL layer fd) for correlation with the
 * read-side ssl_SecureRecv probe in libssl3.so.
 * --------------------------------------------------------------------- */

#define PRIOVEC_STRIDE 16   /* sizeof(PRIOVec) on 64-bit */
#define MAX_WRITEV_IOV 8    /* PR_Writev rejects >16; 8 is ample for H2 */

SEC("uprobe/SSL_writev_entry_cap")
int uprobe_ssl_writev_entry_cap(struct pt_regs *ctx)
{
    __u64 iov_ptr = PT_REGS_PARM2(ctx);
    __u32 iov_cnt = (__u32)PT_REGS_PARM3(ctx);

    if (iov_cnt == 0 || iov_ptr == 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = pid_tgid >> 32;
    __u32 tid      = (__u32)pid_tgid;
    __u32 uid      = (__u32)bpf_get_current_uid_gid();
    __u64 conn_id  = nspr_resolve_conn_id(PT_REGS_PARM1(ctx));
    __u64 ts       = bpf_ktime_get_ns();
    __u8  comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));

    if (iov_cnt > MAX_WRITEV_IOV)
        iov_cnt = MAX_WRITEV_IOV;

    /* Emit one event per iov entry.  Bounded loop — kernel 5.8+ required. */
    for (__u32 i = 0; i < MAX_WRITEV_IOV; i++) {
        if (i >= iov_cnt)
            break;

        __u64 base = 0;
        __u32 len  = 0;

        if (bpf_probe_read_user(&base, sizeof(base),
                (void *)(iov_ptr + (__u64)i * PRIOVEC_STRIDE)) < 0)
            break;
        if (bpf_probe_read_user(&len, sizeof(len),
                (void *)(iov_ptr + (__u64)i * PRIOVEC_STRIDE + 8)) < 0)
            break;

        if (base == 0 || len == 0)
            continue;

        struct ssl_event *ev = bpf_ringbuf_reserve(&ssl_events, sizeof(*ev), 0);
        if (!ev)
            return 0;

        ev->timestamp_ns = ts;
        ev->conn_id      = conn_id;
        ev->pid          = pid;
        ev->tid          = tid;
        ev->uid          = uid;
        ev->is_read      = 0;
        __builtin_memcpy(ev->comm, comm, TASK_COMM_LEN);

        __u32 data_len = len > MAX_SSL_DATA_SIZE ? MAX_SSL_DATA_SIZE : len;
        data_len &= (2 * MAX_SSL_DATA_SIZE - 1);
        ev->data_len = data_len;

        if (bpf_probe_read_user(ev->data, data_len, (void *)base) < 0) {
            bpf_ringbuf_discard(ev, 0);
            continue;
        }

        bpf_ringbuf_submit(ev, 0);
    }

    return 0;
}

/* -----------------------------------------------------------------------
 * NSS ssl_SecureRecv read probe — walks PRFileDesc->lower chain
 *
 * This is a variant of uprobe_ssl_read_entry specifically for NSS's
 * ssl_SecureRecv function in libssl3.so.  It resolves the ConnID by
 * walking fd->lower to the TCP socket (bottom of the NSPR layer stack),
 * matching the write-side probes that also walk to the bottom.
 *
 * The standard uprobe_ssl_read_entry is used for OpenSSL where arg1 is
 * an SSL* pointer (no NSPR layer stack), so it must NOT walk ->lower.
 * --------------------------------------------------------------------- */

SEC("uprobe/SSL_read_entry_nspr")
int uprobe_ssl_read_entry_nspr(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    struct ssl_args args = {
        .buf = PT_REGS_PARM2(ctx),
        .conn_id = nspr_resolve_conn_id(PT_REGS_PARM1(ctx)),
        .num = (__u32)PT_REGS_PARM3(ctx),
    };
    bpf_map_update_elem(&active_ssl_read_args, &tid, &args, BPF_ANY);
    return 0;
}

/* -----------------------------------------------------------------------
 * QUIC key extraction via tls13_HkdfExpandLabelRaw
 *
 * Firefox's neqo (Rust QUIC engine) derives QUIC encryption keys by calling
 * SSL_HkdfExpandLabelWithMech → tls13_HkdfExpandLabelRaw in NSS's libssl3.so.
 * This internal function writes raw key material into a caller-provided buffer.
 *
 * By hooking entry (to capture args) and return (to read the output buffer),
 * we extract the plaintext QUIC keys (key/iv/hp) without any MITM.
 *
 * Signature (9 parameters):
 *   SECStatus tls13_HkdfExpandLabelRaw(
 *       PK11SymKey *prk,           // x0 (ignored)
 *       SSLHashType baseHash,      // w1
 *       const PRUint8 *hsHash,     // x2 (ignored, NULL for QUIC)
 *       unsigned int hsHashLen,     // w3 (ignored)
 *       const char *label,         // x4
 *       unsigned int labelLen,      // w5
 *       SSLProtocolVariant variant, // w6
 *       unsigned char *output,      // x7
 *       unsigned int outputLen      // [sp+0] (9th arg, on stack)
 *   )
 *
 * ARM64: args 1-8 in x0-x7, arg 9 on stack at [sp+0].
 * x86_64: args 1-6 in rdi/rsi/rdx/rcx/r8/r9, args 7-9 on stack.
 * --------------------------------------------------------------------- */

#define MAX_QUIC_KEY_SIZE 48
#define MAX_QUIC_LABEL_LEN 16

struct quic_key_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u8  comm[TASK_COMM_LEN];
    __u8  label[MAX_QUIC_LABEL_LEN];
    __u32 label_len;
    __u32 key_len;
    __u8  key_data[MAX_QUIC_KEY_SIZE];
    __u32 hash_type;
    __u32 variant;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  /* 256 KB — key events are rare (~6 per connection) */
} quic_key_events SEC(".maps");

struct quic_hkdf_args {
    __u64 label_ptr;
    __u64 output_ptr;
    __u32 label_len;
    __u32 output_len;
    __u32 hash_type;
    __u32 variant;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct quic_hkdf_args);
} active_quic_hkdf_args SEC(".maps");

SEC("uprobe/quic_hkdf_expand_entry")
int uprobe_quic_hkdf_expand_entry(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    struct quic_hkdf_args args = {};

#if defined(__TARGET_ARCH_arm64)
    /* ARM64: x4=label, w5=labelLen, w6=variant, x7=output, [sp+0]=outputLen */
    args.label_ptr  = PT_REGS_PARM5(ctx);    /* x4 */
    args.label_len  = (__u32)PT_REGS_PARM6(ctx);  /* w5 */
    args.variant    = (__u32)ctx->regs[6];         /* w6 — no PT_REGS_PARM7 */
    args.output_ptr = ctx->regs[7];                /* x7 */
    args.hash_type  = (__u32)PT_REGS_PARM2(ctx);   /* w1 */
    /* 9th arg is on stack */
    __u32 output_len = 0;
    bpf_probe_read_user(&output_len, sizeof(output_len), (void *)(PT_REGS_SP(ctx)));
    args.output_len = output_len;
#else
    /* x86_64: rdi=prk, rsi=baseHash, rdx=hsHash, rcx=hsHashLen, r8=label, r9=labelLen
     * stack: [rsp+8]=variant, [rsp+16]=output, [rsp+24]=outputLen */
    args.label_ptr  = PT_REGS_PARM5(ctx);    /* r8 */
    args.label_len  = (__u32)PT_REGS_PARM6(ctx);  /* r9 */
    args.hash_type  = (__u32)PT_REGS_PARM2(ctx);   /* rsi */
    __u32 variant = 0;
    bpf_probe_read_user(&variant, sizeof(variant), (void *)(PT_REGS_SP(ctx) + 8));
    args.variant = variant;
    __u64 output_ptr = 0;
    bpf_probe_read_user(&output_ptr, sizeof(output_ptr), (void *)(PT_REGS_SP(ctx) + 16));
    args.output_ptr = output_ptr;
    __u32 output_len = 0;
    bpf_probe_read_user(&output_len, sizeof(output_len), (void *)(PT_REGS_SP(ctx) + 24));
    args.output_len = output_len;
#endif

    bpf_map_update_elem(&active_quic_hkdf_args, &tid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/quic_hkdf_expand_ret")
int uretprobe_quic_hkdf_expand_ret(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    struct quic_hkdf_args *args = bpf_map_lookup_elem(&active_quic_hkdf_args, &tid);
    if (!args)
        return 0;

    /* SECSuccess = 0 */
    int ret = (int)PT_REGS_RC(ctx);
    if (ret != 0)
        goto cleanup;

    __u32 key_len = args->output_len;
    if (key_len == 0 || key_len > MAX_QUIC_KEY_SIZE)
        goto cleanup;

    struct quic_key_event *ev = bpf_ringbuf_reserve(&quic_key_events, sizeof(*ev), 0);
    if (!ev)
        goto cleanup;

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pid          = ((__u64)bpf_get_current_pid_tgid()) >> 32;
    ev->tid          = tid;
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));
    ev->hash_type    = args->hash_type;
    ev->variant      = args->variant;
    ev->key_len      = key_len;

    /* Read the label string. */
    ev->label_len = args->label_len;
    if (ev->label_len > MAX_QUIC_LABEL_LEN)
        ev->label_len = MAX_QUIC_LABEL_LEN;
    /* Ensure verifier sees a bounded read size. */
    __u32 safe_label_len = ev->label_len & (MAX_QUIC_LABEL_LEN - 1);
    if (safe_label_len > 0) {
        if (bpf_probe_read_user(ev->label, safe_label_len, (void *)args->label_ptr) < 0) {
            bpf_ringbuf_discard(ev, 0);
            goto cleanup;
        }
    }

    /* Read the output key data. */
    __u32 safe_key_len = key_len & (MAX_QUIC_KEY_SIZE - 1);
    if (safe_key_len == 0)
        safe_key_len = key_len < MAX_QUIC_KEY_SIZE ? key_len : MAX_QUIC_KEY_SIZE;
    if (bpf_probe_read_user(ev->key_data, safe_key_len, (void *)args->output_ptr) < 0) {
        bpf_ringbuf_discard(ev, 0);
        goto cleanup;
    }

    bpf_ringbuf_submit(ev, 0);

cleanup:
    bpf_map_delete_elem(&active_quic_hkdf_args, &tid);
    return 0;
}

/*
 *
 * Go's TLS stack does not link against libssl.so, so the SSL_read/write
 * uprobes above will not intercept Go HTTPS traffic.
 *
 * To intercept Go TLS, attach uretprobes to the internal Read/Write methods
 * of crypto/tls.(*Conn):
 *
 *   SEC("uretprobe/go_tls_conn_read")
 *   int uretprobe_go_tls_read(struct pt_regs *ctx) { ... }
 *
 *   SEC("uretprobe/go_tls_conn_write")
 *   int uretprobe_go_tls_write(struct pt_regs *ctx) { ... }
 *
 * Symbol lookup for Go binaries requires parsing the Go symbol table
 * (pclntab) since Go uses a non-standard ABI (register-based since 1.17).
 * The Go calling convention passes the receiver in AX, not the stack,
 * and return values are also register-based.
 *
 * This is implemented in internal/tls/go_tls.go (userspace) with the
 * BPF programs to be added in a follow-up.
 */
