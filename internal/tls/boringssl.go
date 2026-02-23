package tls

// BoringSSL support helpers.
//
// BoringSSL is Google's fork of OpenSSL. Its SSL_write / SSL_read function
// signatures are identical to OpenSSL's, so the existing ssl_uprobe.c BPF
// program works without any changes.
//
// The challenge is that BoringSSL is often statically linked into the
// application binary (e.g. Chromium), rather than shipped as a separate
// libssl.so. Three cases are handled:
//
//  1. Dynamic BoringSSL — libboringssl.so loaded at runtime.
//     Detected by scanning /proc/<pid>/maps. Attach by symbol name.
//
//  2. Static BoringSSL with symbols — the binary has SSL_write/SSL_read
//     in its ELF symbol table (.symtab or .dynsym).
//     Detected by scanning the ELF. Attach by symbol name.
//
//  3. Static BoringSSL, stripped — symbols not present (typical Chromium
//     snap/release builds). Requires explicit file offsets in config.
//     Attach via UprobeOptions.Address (bypasses symbol lookup).

import (
	"bufio"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// boringSSlTarget holds a resolved executable path and SSL function offsets
// ready for uprobe attachment.
type boringSSlTarget struct {
	execPath       string // absolute path to the on-disk binary/library
	sslWriteOffset uint64 // file offset of SSL_write; 0 = use symbol lookup
	sslReadOffset  uint64 // file offset of SSL_read;  0 = use symbol lookup
	isDynamic      bool   // true = shared library (symbol table reliable)
	pid            int    // 0 = system-wide; non-zero = scoped to one process
}

// findSSLSymbolOffsets opens an ELF binary and searches both .symtab and
// .dynsym for SSL_write and SSL_read, returning their file offsets.
// Returns an error if either symbol is not found.
func findSSLSymbolOffsets(path string) (writeOff, readOff uint64, err error) {
	f, err := elf.Open(path)
	if err != nil {
		return 0, 0, fmt.Errorf("open ELF %s: %w", path, err)
	}
	defer f.Close()

	var allSyms []elf.Symbol
	if syms, err := f.Symbols(); err == nil {
		allSyms = append(allSyms, syms...)
	}
	if dynsyms, err := f.DynamicSymbols(); err == nil {
		allSyms = append(allSyms, dynsyms...)
	}

	for _, s := range allSyms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Value == 0 {
			continue
		}
		off := symToFileOffset(f, s)
		if off == 0 {
			continue
		}
		switch s.Name {
		case "SSL_write":
			writeOff = off
		case "SSL_read":
			readOff = off
		}
	}

	if writeOff == 0 || readOff == 0 {
		return 0, 0, fmt.Errorf("SSL_write/SSL_read not found in symbol tables of %s", path)
	}
	return writeOff, readOff, nil
}

// symToFileOffset converts an ELF symbol's virtual address to a file offset
// by finding the enclosing executable LOAD segment.
func symToFileOffset(f *elf.File, s elf.Symbol) uint64 {
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}
		if prog.Vaddr <= s.Value && s.Value < prog.Vaddr+prog.Memsz {
			return s.Value - prog.Vaddr + prog.Off
		}
	}
	return 0
}

// isDynamicLib reports whether path looks like a shared library based on
// whether its base name contains ".so".
func isDynamicLib(path string) bool {
	return strings.Contains(filepath.Base(path), ".so")
}

// resolveExecPath resolves a config path to the real on-disk binary path.
// For snap packages, /snap/<name>/current is a symlink to the active revision;
// filepath.EvalSymlinks resolves it to the versioned path that cilium/ebpf
// needs for a valid inode lookup.
// If pid > 0, the process's own /proc/<pid>/exe path is preferred (most accurate).
func resolveExecPath(configPath string, pid int) string {
	if pid > 0 {
		if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
			// Use the proc exe path if it plausibly matches the config path
			// (same final path components, accounting for snap revision vs "current").
			if sameBasePath(exe, configPath) {
				return exe
			}
		}
	}
	if resolved, err := filepath.EvalSymlinks(configPath); err == nil {
		return resolved
	}
	return configPath
}

// sameBasePath reports whether two paths refer to the same binary by comparing
// their last three path components. This handles the common snap pattern where
// the config uses "current" but the running process path has the revision number.
func sameBasePath(a, b string) bool {
	pa := strings.Split(filepath.Clean(a), string(filepath.Separator))
	pb := strings.Split(filepath.Clean(b), string(filepath.Separator))
	n := 3
	if len(pa) < n || len(pb) < n {
		return false
	}
	for i := 1; i <= n; i++ {
		if pa[len(pa)-i] != pb[len(pb)-i] {
			return false
		}
	}
	return true
}

// findDynamicBoringSSlLib scans /proc/<pid>/maps for a dynamically loaded
// BoringSSL shared library and returns its path, or "" if none found.
func findDynamicBoringSSlLib(pid int) string {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		lib := fields[5]
		base := filepath.Base(lib)
		if strings.HasPrefix(base, "libboringssl") || strings.HasPrefix(base, "libbssl") {
			return lib
		}
	}
	return ""
}
