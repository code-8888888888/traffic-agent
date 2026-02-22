// Package parser performs HTTP/1.1 parsing on raw packet payloads captured by
// the TC eBPF program.
//
// Architecture:
//
//	RawPacketEvent  →  HandlePacket  →  TrafficEvent
//
// Each packet payload is inspected independently. If it begins with a valid
// HTTP/1.1 request or response, the metadata is extracted and forwarded to
// the sink. This "per-packet" approach works well for typical HTTP/1.1 traffic
// where request/response headers fit within a single TCP segment. Multi-packet
// reassembly (required for large requests or chunked responses) is a TODO that
// requires adding TCP sequence numbers to the BPF event struct.
package parser

import (
	"bufio"
	"bytes"
	"net/http"
	"strings"
	"time"

	"github.com/traffic-agent/traffic-agent/internal/types"
)

// EventSink receives fully-parsed TrafficEvents.
type EventSink func(*types.TrafficEvent)

// Parser inspects raw packet payloads and emits HTTP traffic events.
type Parser struct {
	sink EventSink
}

// New creates a Parser that will call sink for each parsed HTTP event.
func New(sink EventSink) *Parser {
	return &Parser{sink: sink}
}

// HandlePacket attempts to parse an HTTP request or response from ev.Payload.
// Events that do not start with a valid HTTP message are silently discarded.
func (p *Parser) HandlePacket(ev *types.RawPacketEvent) {
	if len(ev.Payload) == 0 {
		return
	}

	r := bufio.NewReader(bytes.NewReader(ev.Payload))

	if isClientPort(ev.DstPort) {
		// Destination is a well-known server port → parse as client→server request.
		req, err := http.ReadRequest(r)
		if err != nil {
			return
		}
		defer req.Body.Close()

		te := &types.TrafficEvent{
			Timestamp:      time.Now(),
			SrcIP:          ev.SrcIP.String(),
			DstIP:          ev.DstIP.String(),
			SrcPort:        ev.SrcPort,
			DstPort:        ev.DstPort,
			Protocol:       "TCP",
			Direction:      ev.Direction.String(),
			HTTPMethod:     req.Method,
			URL:            req.URL.String(),
			RequestHeaders: headersToMap(req.Header),
		}
		if body := readBodySnippet(req.Body); len(body) > 0 {
			te.BodySnippet = string(body)
		}
		p.sink(te)

	} else if isServerPort(ev.SrcPort) {
		// Source is a well-known server port → parse as server→client response.
		resp, err := http.ReadResponse(r, nil)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		te := &types.TrafficEvent{
			Timestamp:       time.Now(),
			SrcIP:           ev.SrcIP.String(),
			DstIP:           ev.DstIP.String(),
			SrcPort:         ev.SrcPort,
			DstPort:         ev.DstPort,
			Protocol:        "TCP",
			Direction:       ev.Direction.String(),
			StatusCode:      resp.StatusCode,
			ResponseHeaders: headersToMap(resp.Header),
		}
		if body := readBodySnippet(resp.Body); len(body) > 0 {
			te.BodySnippet = string(body)
		}
		p.sink(te)
	}
}

// FlushExpired is a no-op retained for interface compatibility. TCP stream
// reassembly (which requires flushing stale streams) is not used in the
// per-packet parsing model.
func (p *Parser) FlushExpired(_ time.Duration) {}

// ---- Helpers ----

// isClientPort returns true when the destination port is a well-known HTTP/S port,
// indicating the packet flows from client to server.
func isClientPort(dstPort uint16) bool {
	return dstPort == 80 || dstPort == 443 || dstPort == 8080 || dstPort == 8443
}

// isServerPort returns true when the source port is a well-known HTTP/S port,
// indicating the packet flows from server to client.
func isServerPort(srcPort uint16) bool {
	return srcPort == 80 || srcPort == 443 || srcPort == 8080 || srcPort == 8443
}

func headersToMap(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, vs := range h {
		m[k] = strings.Join(vs, ", ")
	}
	return m
}

func readBodySnippet(body interface{ Read([]byte) (int, error) }) []byte {
	if body == nil {
		return nil
	}
	buf := make([]byte, types.BodySnippetMaxLen)
	n, _ := body.Read(buf)
	if n <= 0 {
		return nil
	}
	return buf[:n]
}
