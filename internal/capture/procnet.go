package capture

// lookupTCPProcess resolves the PID and process name for a TCP connection by
// scanning /proc/net/tcp and then /proc/<pid>/fd/.
//
// LookupTCPProcessCached wraps the raw lookup with a TTL cache so that the
// expensive /proc scan is amortised across many packets on the same connection.

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---- Process lookup cache ----

// procKey identifies a TCP 4-tuple for caching.
type procKey struct {
	srcIP   [4]byte
	srcPort uint16
	dstIP   [4]byte
	dstPort uint16
}

// procEntry is a cached process lookup result.
type procEntry struct {
	pid       uint32
	comm      string
	timestamp time.Time
}

const procCacheTTL = 30 * time.Second

// procCache is a concurrent-safe TTL cache for process lookups.
type procCache struct {
	mu      sync.RWMutex
	entries map[procKey]procEntry
}

var globalProcCache = &procCache{
	entries: make(map[procKey]procEntry),
}

func makeProcKey(srcIP, dstIP net.IP, srcPort, dstPort uint16) procKey {
	var k procKey
	copy(k.srcIP[:], srcIP.To4())
	copy(k.dstIP[:], dstIP.To4())
	k.srcPort = srcPort
	k.dstPort = dstPort
	return k
}

// LookupTCPProcessCached resolves PID/comm for a packet, using a TTL cache
// to avoid repeated /proc scans. Safe to call from multiple goroutines.
func LookupTCPProcessCached(srcIP, dstIP net.IP, srcPort, dstPort uint16, direction uint8) (uint32, string) {
	// For egress: local=src; for ingress: local=dst.
	var localIP, remoteIP net.IP
	var localPort, remotePort uint16
	if direction == 1 { // DIR_EGRESS
		localIP, localPort = srcIP, srcPort
		remoteIP, remotePort = dstIP, dstPort
	} else {
		localIP, localPort = dstIP, dstPort
		remoteIP, remotePort = srcIP, srcPort
	}

	key := makeProcKey(srcIP, dstIP, srcPort, dstPort)

	// Check cache (read lock).
	globalProcCache.mu.RLock()
	if entry, ok := globalProcCache.entries[key]; ok && time.Since(entry.timestamp) < procCacheTTL {
		globalProcCache.mu.RUnlock()
		return entry.pid, entry.comm
	}
	globalProcCache.mu.RUnlock()

	// Cache miss — do the expensive /proc scan.
	pid, comm := lookupTCPProcess(localIP, localPort, remoteIP, remotePort)

	// Store result (even zero/empty — avoids repeated scans for unknown connections).
	globalProcCache.mu.Lock()
	globalProcCache.entries[key] = procEntry{
		pid:       pid,
		comm:      comm,
		timestamp: time.Now(),
	}
	globalProcCache.mu.Unlock()

	return pid, comm
}

// PurgeProcCache removes expired entries. Call periodically from a maintenance goroutine.
func PurgeProcCache() {
	now := time.Now()
	globalProcCache.mu.Lock()
	for k, v := range globalProcCache.entries {
		if now.Sub(v.timestamp) > procCacheTTL {
			delete(globalProcCache.entries, k)
		}
	}
	globalProcCache.mu.Unlock()
}

// ---- Raw /proc lookups (unchanged) ----

// lookupTCPProcess finds the PID and comm for a TCP 4-tuple.
// Returns (0, "") when no match is found.
func lookupTCPProcess(localIP net.IP, localPort uint16, remoteIP net.IP, remotePort uint16) (uint32, string) {
	inode := findTCPSocketInode(localIP, localPort, remoteIP, remotePort)
	if inode == 0 {
		return 0, ""
	}
	return findPIDBySocketInode(inode)
}

// findTCPSocketInode returns the socket inode from /proc/net/tcp for the
// given local/remote address pair. Returns 0 if not found.
func findTCPSocketInode(localIP net.IP, localPort uint16, remoteIP net.IP, remotePort uint16) uint64 {
	localHex := ipv4ToHex(localIP)
	remoteHex := ipv4ToHex(remoteIP)
	if localHex == "" || remoteHex == "" {
		return 0
	}
	want := fmt.Sprintf("%s:%04X %s:%04X", localHex, localPort, remoteHex, remotePort)

	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		return 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header line
	for scanner.Scan() {
		line := scanner.Text()
		// Fast path: check the address fields before splitting
		if !strings.Contains(line, localHex) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		if fields[1]+" "+fields[2] == want {
			inode, _ := strconv.ParseUint(fields[9], 10, 64)
			return inode
		}
	}
	return 0
}

// ipv4ToHex converts an IPv4 address to the 8-char uppercase hex string used
// in /proc/net/tcp. On little-endian hosts the bytes are reversed.
//
// Example: 192.168.68.61 → "3D44A8C0" (on little-endian / ARM64 / x86-64)
func ipv4ToHex(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	// binary.LittleEndian.Uint32 interprets the 4-byte slice as little-endian,
	// but ip4 is in network (big-endian) order. On a LE host, the kernel stores
	// the __be32 at its memory address and %08X prints the native-endian view,
	// which is the byte-swapped value.
	val := binary.LittleEndian.Uint32(ip4)
	return fmt.Sprintf("%08X", val)
}

// findPIDBySocketInode scans /proc/*/fd/ for a symlink pointing to
// "socket:[inode]" and returns the owning PID and process name.
func findPIDBySocketInode(inode uint64) (uint32, string) {
	target := fmt.Sprintf("socket:[%d]", inode)

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, ""
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pidNum, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}

		fdDir := fmt.Sprintf("/proc/%d/fd", pidNum)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if link == target {
				commBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pidNum))
				if err != nil {
					return uint32(pidNum), ""
				}
				return uint32(pidNum), strings.TrimSpace(string(commBytes))
			}
		}
	}
	return 0, ""
}
