// Package parser performs HTTP/1.1 parsing on raw packet payloads captured by
// the TC eBPF program and on plaintext data captured by SSL uprobes.
//
// Architecture:
//
//	RawPacketEvent  →  HandlePacket   →  per-flow buffer  →  TrafficEvent
//	SSLEvent        →  HandleSSLEvent →  per-flow buffer  →  TrafficEvent
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
	"compress/gzip"
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

// sslFlowKey identifies a per-thread SSL data stream.
type sslFlowKey struct {
	PID    uint32
	TID    uint32
	IsRead bool
}

type flowBuf struct {
	data          []byte
	updated       time.Time
	lastParsedAt  time.Time // set when a complete message was last emitted
}

// Parser accumulates per-flow payloads and emits HTTP traffic events.
type Parser struct {
	sink    EventSink
	mu      sync.Mutex
	bufs    map[flowKey]*flowBuf
	sslBufs map[sslFlowKey]*flowBuf
}

// New creates a Parser that will call sink for each parsed HTTP event.
func New(sink EventSink) *Parser {
	return &Parser{
		sink:    sink,
		bufs:    make(map[flowKey]*flowBuf),
		sslBufs: make(map[sslFlowKey]*flowBuf),
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
		// Skip if this flow was parsed very recently (suppresses TCP retransmit duplicates).
		p.mu.Lock()
		cooldown := !p.bufs[key].lastParsedAt.IsZero() &&
			time.Since(p.bufs[key].lastParsedAt) < 3*time.Second
		p.mu.Unlock()
		if !cooldown {
			p.tryParseRequest(key, data, ev)
		}
	} else if isServerPort(ev.SrcPort) {
		p.tryParseResponse(key, data, ev)
	}
}

// HandleSSLEvent appends ev.Data to the per-SSL-stream buffer and attempts to
// parse a complete HTTP request or response from the accumulated plaintext.
func (p *Parser) HandleSSLEvent(ev *types.SSLEvent) {
	if len(ev.Data) == 0 {
		return
	}

	key := sslFlowKey{PID: ev.PID, TID: ev.TID, IsRead: ev.IsRead}

	p.mu.Lock()
	fb, ok := p.sslBufs[key]
	if !ok {
		fb = &flowBuf{}
		p.sslBufs[key] = fb
	}
	if len(fb.data)+len(ev.Data) <= maxFlowBufSize {
		fb.data = append(fb.data, ev.Data...)
	}
	fb.updated = time.Now()
	data := make([]byte, len(fb.data))
	copy(data, fb.data)
	p.mu.Unlock()

	if !ev.IsRead {
		// HTTP/2 cleartext connection preface — discard, we can't parse HTTP/2 framing.
		if bytes.HasPrefix(data, []byte("PRI * HTTP/2.0")) {
			p.deleteSSLBuf(key)
			return
		}
		// SSL_write: process is sending plaintext → HTTP request (egress).
		fields, ok := parseHTTPRequestFields(data)
		if !ok {
			return
		}
		te := &types.TrafficEvent{
			Timestamp:      time.Now(),
			Protocol:       "TLS",
			Direction:      "egress",
			PID:            ev.PID,
			ProcessName:    ev.ProcessName,
			HTTPMethod:     fields.method,
			URL:            fields.url,
			RequestHeaders: fields.headers,
			BodySnippet:    fields.body,
			TLSIntercepted: true,
		}
		p.sink(te)
		p.deleteSSLBuf(key)
	} else {
		// SSL_read: process is receiving plaintext → HTTP response (ingress).
		fields, ok := parseHTTPResponseFields(data)
		if !ok {
			return
		}
		te := &types.TrafficEvent{
			Timestamp:       time.Now(),
			Protocol:        "TLS",
			Direction:       "ingress",
			PID:             ev.PID,
			ProcessName:     ev.ProcessName,
			StatusCode:      fields.statusCode,
			ResponseHeaders: fields.headers,
			BodySnippet:     fields.body,
			TLSIntercepted:  true,
		}
		p.sink(te)
		p.deleteSSLBuf(key)
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
	for key, fb := range p.sslBufs {
		if fb.updated.Before(cutoff) {
			delete(p.sslBufs, key)
		}
	}
}

// ---- Internal parse helpers (TC packet events) ----

func (p *Parser) tryParseRequest(key flowKey, data []byte, ev *types.RawPacketEvent) {
	// HTTP/2 cleartext sends a connection preface starting with "PRI * HTTP/2.0".
	// We can't parse HTTP/2 binary framing; skip silently to avoid log noise.
	if bytes.HasPrefix(data, []byte("PRI * HTTP/2.0")) {
		p.deleteBuf(key)
		return
	}

	fields, ok := parseHTTPRequestFields(data)
	if !ok {
		return
	}
	te := &types.TrafficEvent{
		Timestamp:      time.Now(),
		SrcIP:          ev.SrcIP.String(),
		DstIP:          ev.DstIP.String(),
		SrcPort:        ev.SrcPort,
		DstPort:        ev.DstPort,
		Protocol:       "TCP",
		Direction:      ev.Direction.String(),
		PID:            ev.PID,
		ProcessName:    ev.ProcessName,
		HTTPMethod:     fields.method,
		URL:            fields.url,
		RequestHeaders: fields.headers,
		BodySnippet:    fields.body,
	}
	p.sink(te)
	p.mu.Lock()
	if fb := p.bufs[key]; fb != nil {
		fb.data = nil
		fb.lastParsedAt = time.Now()
	}
	p.mu.Unlock()
}

func (p *Parser) tryParseResponse(key flowKey, data []byte, ev *types.RawPacketEvent) {
	fields, ok := parseHTTPResponseFields(data)
	if !ok {
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
		PID:             ev.PID,
		ProcessName:     ev.ProcessName,
		StatusCode:      fields.statusCode,
		ResponseHeaders: fields.headers,
		BodySnippet:     fields.body,
	}
	p.sink(te)
	p.mu.Lock()
	if fb := p.bufs[key]; fb != nil {
		fb.data = nil
		fb.lastParsedAt = time.Now()
	}
	p.mu.Unlock()
}

func (p *Parser) deleteBuf(key flowKey) {
	p.mu.Lock()
	delete(p.bufs, key)
	p.mu.Unlock()
}

func (p *Parser) deleteSSLBuf(key sslFlowKey) {
	p.mu.Lock()
	delete(p.sslBufs, key)
	p.mu.Unlock()
}

// ---- Shared HTTP parsing helpers ----

type httpRequestFields struct {
	method  string
	url     string
	headers map[string]string
	body    string
}

type httpResponseFields struct {
	statusCode int
	headers    map[string]string
	body       string
}

// parseHTTPRequestFields attempts to parse an HTTP/1.1 request from data.
// Returns (nil, false) if the message is incomplete or not HTTP.
func parseHTTPRequestFields(data []byte) (*httpRequestFields, bool) {
	r := bufio.NewReader(bytes.NewReader(data))
	req, err := http.ReadRequest(r)
	if err != nil {
		return nil, false
	}
	defer req.Body.Close()

	bodyBuf := make([]byte, types.BodySnippetMaxLen)
	bodyN, _ := io.ReadAtLeast(req.Body, bodyBuf, 1)
	if bodyN < 0 {
		bodyN = 0
	}

	// If Content-Length is known and we haven't received all of it (and
	// haven't yet filled the snippet buffer), wait for the next segment.
	contentLen := int(req.ContentLength)
	bodyComplete := contentLen <= 0 || bodyN >= contentLen
	snippetFull := bodyN >= types.BodySnippetMaxLen
	if !bodyComplete && !snippetFull {
		return nil, false
	}

	headers := headersToMap(req.Header)
	if req.Host != "" {
		headers["Host"] = req.Host
	}

	body := ""
	if bodyN > 0 {
		body = string(bodyBuf[:bodyN])
	}

	return &httpRequestFields{
		method:  req.Method,
		url:     req.URL.String(),
		headers: headers,
		body:    body,
	}, true
}

// parseHTTPResponseFields attempts to parse an HTTP/1.1 response from data.
// Returns (nil, false) if the message is incomplete or not HTTP.
func parseHTTPResponseFields(data []byte) (*httpResponseFields, bool) {
	r := bufio.NewReader(bytes.NewReader(data))
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		// Headers not yet fully buffered — keep accumulating.
		return nil, false
	}
	defer resp.Body.Close()

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
		return nil, false
	}

	body := ""
	if bodyN > 0 {
		rawBody := bodyBuf[:bodyN]
		if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
			body = decompressGzip(rawBody)
		} else {
			body = string(rawBody)
		}
	}

	return &httpResponseFields{
		statusCode: resp.StatusCode,
		headers:    headersToMap(resp.Header),
		body:       body,
	}, true
}

// decompressGzip attempts to decompress gzip-encoded data and returns up to
// BodySnippetMaxLen bytes of the decompressed content as a string.
// Returns "<gzip-compressed>" if the data cannot be decompressed.
func decompressGzip(data []byte) string {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return "<gzip-compressed>"
	}
	defer gr.Close()
	out := make([]byte, types.BodySnippetMaxLen)
	n, err := io.ReadAtLeast(gr, out, 1)
	if err != nil && n == 0 {
		return "<gzip-compressed>"
	}
	return string(out[:n])
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
