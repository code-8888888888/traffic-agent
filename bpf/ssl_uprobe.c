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
 *   arg1 (x0) = context pointer (ignored)
 *   arg2 (x1) = buf  — plaintext data to write
 *   arg3 (x2) = num  — byte count
 * --------------------------------------------------------------------- */

SEC("uprobe/SSL_write_entry_cap")
int uprobe_ssl_write_entry_cap(struct pt_regs *ctx)
{
    void  *buf = (void *)PT_REGS_PARM2(ctx);
    __u32  num = (__u32)PT_REGS_PARM3(ctx);

    if (num == 0)
        return 0;

    struct ssl_event *ev = bpf_ringbuf_reserve(&ssl_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->conn_id      = PT_REGS_PARM1(ctx);
    ev->pid          = ((__u64)bpf_get_current_pid_tgid()) >> 32;
    ev->tid          = (__u32)bpf_get_current_pid_tgid();
    ev->uid          = (__u32)bpf_get_current_uid_gid();
    ev->is_read      = 0;
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    __u32 data_len = num > MAX_SSL_DATA_SIZE ? MAX_SSL_DATA_SIZE : num;
    ev->data_len = data_len;

    if (bpf_probe_read_user(ev->data, data_len, buf) < 0) {
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/*
 * TODO: Go crypto/tls interception
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
