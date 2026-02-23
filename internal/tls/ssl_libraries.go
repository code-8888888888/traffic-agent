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
}

// sslLibFound holds a resolved shared-library path and the function names to
// attach uprobes to.
type sslLibFound struct {
	path      string
	writeFunc string
	readFunc  string
	tailCall  bool
}

// findSSLLibsForPID reads /proc/<pid>/maps and returns every loaded shared
// library that matches a known SSL/TLS library definition.
// Duplicate paths within the same process are deduplicated.
func findSSLLibsForPID(pid int) []sslLibFound {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := make(map[string]bool)
	var found []sslLibFound

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
		base := filepath.Base(libPath)
		for _, def := range knownSSLLibDefs {
			if strings.Contains(base, def.namePattern) {
				found = append(found, sslLibFound{
					path:      libPath,
					writeFunc: def.writeFunc,
					readFunc:  def.readFunc,
					tailCall:  def.tailCall,
				})
				seen[libPath] = true
				break
			}
		}
	}
	return found
}
