package capture

// lookupTCPProcess resolves the PID and process name for a TCP connection by
// scanning /proc/net/tcp and then /proc/<pid>/fd/.
//
// localIP:localPort is the address on this machine (src for egress, dst for
// ingress). remoteIP:remotePort is the peer address.
//
// This is a best-effort, zero-BPF-helper approach that works for any
// BPF program type. The cost is two /proc reads per event; acceptable for
// HTTP traffic volumes.

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

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
