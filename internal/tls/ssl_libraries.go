package tls

// Universal SSL library detection.
//
// Rather than hard-coding a single library path, the agent scans every running
// process's memory maps for any of the known SSL/TLS shared libraries.  All of
// the listed libraries share a compatible calling convention for their write and
// read functions:
//
//	func(context, buf *byte, len int) int
//
// with buf at PARM2 (x1 on ARM64) and len at PARM3 (x2), which is exactly
// what ssl_uprobe.c reads.  This means one BPF program can intercept plaintext
// from OpenSSL, BoringSSL, GnuTLS, and NSS/NSPR with no changes.

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// sslLibDef maps a library name substring to the write/read function names
// that carry plaintext data.
type sslLibDef struct {
	namePattern string // matched against filepath.Base(libPath)
	writeFunc   string
	readFunc    string
	// tailCall indicates that writeFunc (and readFunc) are indirect tail-calls
	// (e.g. ARM64 "br x3") rather than normal functions with a RET instruction.
	// When true, uretprobes will never fire, so the agent uses an entry-only
	// capture program for writes and skips read probes entirely.
	// NSS/NSPR's PR_Write and PR_Read are the primary examples.
	tailCall bool
	// isWritev indicates that writeFunc takes a scatter-gather iov array
	// (fd, iov, count, timeout) instead of a direct buffer (fd, buf, len).
	// Requires the writev-specific BPF program.
	isWritev bool
}

// knownSSLLibDefs is the table of all SSL/TLS libraries whose I/O functions
// are ABI-compatible with our BPF uprobe programs.
var knownSSLLibDefs = []sslLibDef{
	// OpenSSL — all versions (libssl.so.3, libssl.so.1.1, libssl.so)
	{namePattern: "libssl.so", writeFunc: "SSL_write", readFunc: "SSL_read"},
	// BoringSSL shipped as a shared library (libboringssl.so, libboringssl_*.so)
	{namePattern: "libboringssl", writeFunc: "SSL_write", readFunc: "SSL_read"},
	// GnuTLS — used by wget, glib networking, some system tools
	{namePattern: "libgnutls.so", writeFunc: "gnutls_record_send", readFunc: "gnutls_record_recv"},
	// NSS via NSPR — used by Firefox, Thunderbird.
	// PR_Write and PR_Read are 3-instruction indirect tail-calls on ARM64;
	// uretprobes will never fire.  Use entry-only write capture instead.
	{namePattern: "libnspr4.so", writeFunc: "PR_Write", readFunc: "PR_Read", tailCall: true},
	// PR_Send/PR_Recv — socket-specific NSPR I/O used by Firefox's HTTP/2 stack.
	// Same ABI as PR_Write/PR_Read (fd, buf, len as first 3 params), same tail-call.
	// Firefox uses PR_Send for H2 frame writes, PR_Write for H1 and IPC.
	{namePattern: "libnspr4.so", writeFunc: "PR_Send", readFunc: "PR_Recv", tailCall: true},
	// PR_Writev — scatter-gather write used by Firefox's HTTP/2 engine.
	// Different ABI: (fd, iov_array, iov_count, timeout) instead of (fd, buf, len).
	// Requires a dedicated BPF program that reads the PRIOVec array.
	// Same tail-call pattern as PR_Write (ldr; ldr; br on ARM64).
	{namePattern: "libnspr4.so", writeFunc: "PR_Writev", readFunc: "", tailCall: true, isWritev: true},
}

// sslLibFound holds a resolved shared-library path and the function names to
// attach uprobes to.
type sslLibFound struct {
	path      string
	writeFunc string
	readFunc  string
	tailCall  bool
	isWritev  bool
	// Offset-based attachment (for NSS libssl3.so internal functions).
	// When non-zero, uprobes are attached by file offset instead of symbol name.
	writeOffset uint64
	readOffset  uint64
}

// findSSLLibsForPID reads /proc/<pid>/maps and returns every loaded shared
// library that matches a known SSL/TLS library definition.
// Duplicate paths within the same process are deduplicated.
//
// Additionally, it detects NSS's libssl3.so (used by Firefox) and attempts
// to find the internal ssl_DefSend/ssl_DefRecv functions by binary analysis.
// These carry plaintext before/after encryption and support both read and
// write capture (unlike PR_Write/PR_Read which carry ciphertext on ARM64).
func findSSLLibsForPID(pid int) []sslLibFound {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := make(map[string]bool)
	var found []sslLibFound

	// First pass: collect all library paths and detect libssl3.so.
	var libPaths []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		libPath := fields[5]
		if !strings.HasPrefix(libPath, "/") || seen[libPath] {
			continue
		}
		seen[libPath] = true
		libPaths = append(libPaths, libPath)
	}

	// Check for NSS's libssl3.so — if found, we get an internal function
	// that provides incoming plaintext (HTTP responses) at return time.
	// Outgoing plaintext (HTTP requests) is still captured via PR_Write
	// on libnspr4.so (which is kept — not skipped).
	for _, libPath := range libPaths {
		base := filepath.Base(libPath)
		if strings.Contains(base, "libssl3.so") {
			readOff, err := findNSSReadOffset(libPath)
			if err == nil && readOff > 0 {
				found = append(found, sslLibFound{
					path:       libPath,
					readFunc:   "nss_recv_func",
					readOffset: readOff,
				})
			}
		}
	}

	// Second pass: add standard SSL libraries (including libnspr4.so for
	// outgoing plaintext via PR_Write and PR_Send entry-only capture).
	for _, libPath := range libPaths {
		base := filepath.Base(libPath)
		matched := ""
		for _, def := range knownSSLLibDefs {
			if strings.Contains(base, def.namePattern) {
				// Prevent double-match: if a different pattern already matched
				// this library, skip (e.g. "libssl.so" matching "libboringssl.so").
				// But allow the same pattern to match multiple times (e.g. two
				// libnspr4.so entries for PR_Write and PR_Send).
				if matched != "" && matched != def.namePattern {
					continue
				}
				matched = def.namePattern
				found = append(found, sslLibFound{
					path:      libPath,
					writeFunc: def.writeFunc,
					readFunc:  def.readFunc,
					tailCall:  def.tailCall,
					isWritev:  def.isWritev,
				})
			}
		}
	}

	return found
}
