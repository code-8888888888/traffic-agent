// Package filter applies user-defined rules to traffic events, discarding
// events that do not match the configured criteria.
package filter

import (
	"net"

	"github.com/traffic-agent/traffic-agent/internal/config"
	"github.com/traffic-agent/traffic-agent/internal/types"
)

// Filter decides whether a TrafficEvent should be forwarded to output.
type Filter struct {
	srcIPs    []net.IP
	dstIPs    []net.IP
	srcPorts  map[uint16]struct{}
	dstPorts  map[uint16]struct{}
	pids      map[uint32]struct{}
	processes map[string]struct{}
}

// New constructs a Filter from the provided FilterConfig.
// An empty / zero FilterConfig means "allow everything".
func New(cfg config.FilterConfig) (*Filter, error) {
	f := &Filter{
		srcPorts:  make(map[uint16]struct{}),
		dstPorts:  make(map[uint16]struct{}),
		pids:      make(map[uint32]struct{}),
		processes: make(map[string]struct{}),
	}

	for _, ipStr := range cfg.SrcIPs {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, &invalidIPError{ipStr}
		}
		f.srcIPs = append(f.srcIPs, ip)
	}
	for _, ipStr := range cfg.DstIPs {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, &invalidIPError{ipStr}
		}
		f.dstIPs = append(f.dstIPs, ip)
	}
	for _, p := range cfg.SrcPorts {
		f.srcPorts[uint16(p)] = struct{}{}
	}
	for _, p := range cfg.DstPorts {
		f.dstPorts[uint16(p)] = struct{}{}
	}
	for _, pid := range cfg.PIDs {
		f.pids[uint32(pid)] = struct{}{}
	}
	for _, name := range cfg.Processes {
		f.processes[name] = struct{}{}
	}

	return f, nil
}

// Allow returns true if the event passes all configured filter rules.
// A rule with no entries (empty slice/map) is treated as a wildcard.
func (f *Filter) Allow(ev *types.TrafficEvent) bool {
	if len(f.srcIPs) > 0 && !matchIP(f.srcIPs, ev.SrcIP) {
		return false
	}
	if len(f.dstIPs) > 0 && !matchIP(f.dstIPs, ev.DstIP) {
		return false
	}
	if len(f.srcPorts) > 0 {
		if _, ok := f.srcPorts[ev.SrcPort]; !ok {
			return false
		}
	}
	if len(f.dstPorts) > 0 {
		if _, ok := f.dstPorts[ev.DstPort]; !ok {
			return false
		}
	}
	if len(f.pids) > 0 && ev.PID != 0 {
		if _, ok := f.pids[ev.PID]; !ok {
			return false
		}
	}
	if len(f.processes) > 0 && ev.ProcessName != "" {
		if _, ok := f.processes[ev.ProcessName]; !ok {
			return false
		}
	}
	return true
}

// AllowRaw returns true if a raw packet event passes the filter.
// Used for early-stage filtering before HTTP parsing.
func (f *Filter) AllowRaw(ev *types.RawPacketEvent) bool {
	if len(f.srcIPs) > 0 && !matchIPNet(f.srcIPs, ev.SrcIP) {
		return false
	}
	if len(f.dstIPs) > 0 && !matchIPNet(f.dstIPs, ev.DstIP) {
		return false
	}
	if len(f.srcPorts) > 0 {
		if _, ok := f.srcPorts[ev.SrcPort]; !ok {
			return false
		}
	}
	if len(f.dstPorts) > 0 {
		if _, ok := f.dstPorts[ev.DstPort]; !ok {
			return false
		}
	}
	return true
}

func matchIP(list []net.IP, addrStr string) bool {
	addr := net.ParseIP(addrStr)
	if addr == nil {
		return false
	}
	return matchIPNet(list, addr)
}

func matchIPNet(list []net.IP, addr net.IP) bool {
	for _, ip := range list {
		if ip.Equal(addr) {
			return true
		}
	}
	return false
}

type invalidIPError struct{ ip string }

func (e *invalidIPError) Error() string {
	return "invalid IP address in filter config: " + e.ip
}
