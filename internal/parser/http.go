// Package parser performs HTTP/1.1 parsing on raw packet payloads captured by
// the TC eBPF program.
//
// Architecture:
//
//	RawPacketEvent  →  HandlePacket  →  per-flow buffer  →  TrafficEvent
//
// Payloads are accumulated in a per-flow (4-tuple) ring until a complete HTTP
// message can be parsed. For responses, the event is held back until the body
// bytes indicated by Content-Length are available (or the snippet limit is
// reached), so the body_snippet field is populated even when the response
// headers and body arrive in separate TCP segments.
//
// Limitation: TCP sequence numbers are not captured by the BPF program, so
// out-of-order segment reassembly is not supported. In-order delivery (the
// common case) works correctly.
package parser

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/traffic-agent/traffic-agent/internal/types"
)

const maxFlowBufSize = 256 * 1024 // 256 KB max accumulated per flow

// EventSink receives fully-parsed TrafficEvents.
type EventSink func(*types.TrafficEvent)

type flowKey struct {
	srcIP   string
	dstIP   string
	srcPort uint16
	dstPort uint16
}

type flowBuf struct {
	data    []byte
	updated time.Time
}

// Parser accumulates per-flow payloads and emits HTTP traffic events.
type Parser struct {
	sink EventSink
	mu   sync.Mutex
	bufs map[flowKey]*flowBuf
}

// New creates a Parser that will call sink for each parsed HTTP event.
func New(sink EventSink) *Parser {
	return &Parser{
		sink: sink,
		bufs: make(map[flowKey]*flowBuf),
	}
}

// HandlePacket appends ev.Payload to the per-flow buffer and attempts to
// parse a complete HTTP request or response from the accumulated data.
func (p *Parser) HandlePacket(ev *types.RawPacketEvent) {
	if len(ev.Payload) == 0 {
		return
	}

	key := flowKey{
		srcIP:   ev.SrcIP.String(),
		dstIP:   ev.DstIP.String(),
		srcPort: ev.SrcPort,
		dstPort: ev.DstPort,
	}

	p.mu.Lock()
	fb, ok := p.bufs[key]
	if !ok {
		fb = &flowBuf{}
		p.bufs[key] = fb
	}
	if len(fb.data)+len(ev.Payload) <= maxFlowBufSize {
		fb.data = append(fb.data, ev.Payload...)
	}
	fb.updated = time.Now()
	// Snapshot the buffer so we can release the lock before parsing.
	data := make([]byte, len(fb.data))
	copy(data, fb.data)
	p.mu.Unlock()

	if isClientPort(ev.DstPort) {
		p.tryParseRequest(key, data, ev)
	} else if isServerPort(ev.SrcPort) {
		p.tryParseResponse(key, data, ev)
	}
}

// FlushExpired removes stale flow buffers that have been idle longer than
// olderThan. Call this periodically to prevent unbounded memory growth.
func (p *Parser) FlushExpired(olderThan time.Duration) {
	cutoff := time.Now().Add(-olderThan)
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, fb := range p.bufs {
		if fb.updated.Before(cutoff) {
			delete(p.bufs, key)
		}
	}
}

// ---- Internal parse helpers ----

func (p *Parser) tryParseRequest(key flowKey, data []byte, ev *types.RawPacketEvent) {
	r := bufio.NewReader(bytes.NewReader(data))
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
	p.deleteBuf(key)
}

func (p *Parser) tryParseResponse(key flowKey, data []byte, ev *types.RawPacketEvent) {
	r := bufio.NewReader(bytes.NewReader(data))
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		// Headers not yet fully buffered — keep accumulating.
		return
	}
	defer resp.Body.Close()

	// Read available body bytes (up to snippet limit).
	bodyBuf := make([]byte, types.BodySnippetMaxLen)
	bodyN, _ := io.ReadAtLeast(resp.Body, bodyBuf, 1)
	if bodyN < 0 {
		bodyN = 0
	}

	// If Content-Length is known and we haven't received all of it (and
	// haven't yet filled the snippet buffer), wait for the next segment.
	contentLen := int(resp.ContentLength)
	bodyComplete := contentLen < 0 || bodyN >= contentLen
	snippetFull := bodyN >= types.BodySnippetMaxLen
	if !bodyComplete && !snippetFull {
		return
	}

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
	if bodyN > 0 {
		te.BodySnippet = string(bodyBuf[:bodyN])
	}
	p.sink(te)
	p.deleteBuf(key)
}

func (p *Parser) deleteBuf(key flowKey) {
	p.mu.Lock()
	delete(p.bufs, key)
	p.mu.Unlock()
}

// ---- Helpers ----

func isClientPort(dstPort uint16) bool {
	return dstPort == 80 || dstPort == 443 || dstPort == 8080 || dstPort == 8443
}

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

func readBodySnippet(body io.ReadCloser) []byte {
	if body == nil || body == http.NoBody {
		return nil
	}
	buf := make([]byte, types.BodySnippetMaxLen)
	n, _ := body.Read(buf)
	if n <= 0 {
		return nil
	}
	return buf[:n]
}
