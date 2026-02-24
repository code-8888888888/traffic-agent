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
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/traffic-agent/traffic-agent/internal/types"
)

// Debug counters for diagnostics.
var (
	sslEventsReceived  atomic.Int64
	sslEventsH2Preface atomic.Int64
	sslEventsH2Routed  atomic.Int64
	sslEventsH1Path    atomic.Int64
	sslEventsSkipped   atomic.Int64
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

// sslFlowKey identifies a per-connection SSL data stream.
// ConnID (SSL*/PRFileDesc* pointer) disambiguates multiple connections
// multiplexed on the same thread (e.g. Firefox's Socket Thread).
type sslFlowKey struct {
	PID    uint32
	TID    uint32
	ConnID uint64
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
	h2Conns map[h2ConnKey]*h2ConnState // HTTP/2 connection states keyed by (PID, TID)
}

// New creates a Parser that will call sink for each parsed HTTP event.
func New(sink EventSink) *Parser {
	return &Parser{
		sink:    sink,
		bufs:    make(map[flowKey]*flowBuf),
		sslBufs: make(map[sslFlowKey]*flowBuf),
		h2Conns: make(map[h2ConnKey]*h2ConnState),
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

// SSLEventStats returns a snapshot of debug counters for diagnostics.
func SSLEventStats() (received, h2preface, h2routed, h1path, skipped int64) {
	return sslEventsReceived.Load(), sslEventsH2Preface.Load(),
		sslEventsH2Routed.Load(), sslEventsH1Path.Load(), sslEventsSkipped.Load()
}

// HandleSSLEvent appends ev.Data to the per-SSL-stream buffer and attempts to
// parse a complete HTTP/1.1 or HTTP/2 message from the accumulated plaintext.
func (p *Parser) HandleSSLEvent(ev *types.SSLEvent) {
	if len(ev.Data) == 0 {
		return
	}
	sslEventsReceived.Add(1)

	h2Key := h2ConnKey{PID: ev.PID, TID: ev.TID, ConnID: ev.ConnID}

	// Check whether this (PID, TID) is already tracked as an HTTP/2 connection.
	p.mu.Lock()
	h2State := p.h2Conns[h2Key]
	p.mu.Unlock()

	// Detect HTTP/2 connections from the explicit client connection preface
	// ("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").
	if h2State == nil && isHTTP2Preface(ev.Data) {
		h2State = newH2ConnState()
		p.mu.Lock()
		p.h2Conns[h2Key] = h2State
		p.mu.Unlock()
		sslEventsH2Preface.Add(1)
		log.Printf("[parser] HTTP/2 preface detected PID=%d TID=%d conn=0x%x proc=%s", ev.PID, ev.TID, ev.ConnID, ev.ProcessName)
	}

	// Mid-connection HTTP/2 detection: if no h2ConnState exists yet, check
	// whether the data looks like a valid HTTP/2 frame (HEADERS, SETTINGS,
	// or DATA).  This handles persistent connections whose preface was sent
	// before the agent attached (e.g., Firefox → claude.ai).
	//
	// This is much stricter than the removed looksLikeHTTP2 heuristic:
	// it requires specific frame types with valid semantic constraints, so
	// the false-positive rate from NSPR IPC noise is negligible.
	if h2State == nil && looksLikeH2MidConnection(ev.Data) {
		h2State = newH2ConnState()
		p.mu.Lock()
		p.h2Conns[h2Key] = h2State
		p.mu.Unlock()
		sslEventsH2Preface.Add(1)
		log.Printf("[parser] HTTP/2 mid-connection join PID=%d TID=%d conn=0x%x proc=%s (frame type=0x%02x)",
			ev.PID, ev.TID, ev.ConnID, ev.ProcessName, ev.Data[3])
	}

	if h2State != nil {
		sslEventsH2Routed.Add(1)
		p.handleH2Event(h2State, ev)
		return
	}

	// ---- HTTP/1.1 path ----
	//
	// Try parsing the current event's data alone first.  This handles the
	// common case where a complete HTTP message fits in a single SSL record,
	// and is essential for Firefox's Socket Thread which multiplexes all
	// connections through one (PID, TID) — accumulating across events would
	// mix data from different connections.
	//
	// If single-event parsing fails, fall back to accumulating in a flow
	// buffer (for multi-segment messages on dedicated-thread SSL libs like
	// OpenSSL).

	if te := p.tryParseSSLData(ev.Data, ev); te != nil {
		sslEventsH1Path.Add(1)
		p.sink(te)
		return
	}

	// Single-event parse failed — accumulate and retry, but only if the data
	// could plausibly be HTTP. NSPR's PR_Write fires for ALL I/O (IPC, files,
	// TLS), and accumulating non-HTTP data wastes memory (up to 256KB per
	// flow) and CPU (re-parse attempt on every new event).
	key := sslFlowKey{PID: ev.PID, TID: ev.TID, ConnID: ev.ConnID, IsRead: ev.IsRead}

	p.mu.Lock()
	fb := p.sslBufs[key]
	p.mu.Unlock()

	if fb == nil {
		// New flow — only start accumulating if the data looks like HTTP.
		if !looksLikeHTTPStart(ev.Data, ev.IsRead) {
			sslEventsSkipped.Add(1)
			return
		}
		p.mu.Lock()
		fb = &flowBuf{}
		p.sslBufs[key] = fb
		p.mu.Unlock()
	}

	p.mu.Lock()
	if len(fb.data)+len(ev.Data) <= maxFlowBufSize {
		fb.data = append(fb.data, ev.Data...)
	}
	fb.updated = time.Now()
	data := make([]byte, len(fb.data))
	copy(data, fb.data)
	p.mu.Unlock()

	if te := p.tryParseSSLData(data, ev); te != nil {
		sslEventsH1Path.Add(1)
		p.sink(te)
		p.deleteSSLBuf(key)
	}
}

// tryParseSSLData attempts to parse data as an HTTP/1.1 request or response
// based on the event's IsRead flag.  Returns nil if parsing fails.
func (p *Parser) tryParseSSLData(data []byte, ev *types.SSLEvent) *types.TrafficEvent {
	if !ev.IsRead {
		fields, ok := parseHTTPRequestFields(data)
		if !ok {
			return nil
		}
		return &types.TrafficEvent{
			Timestamp:      time.Now(),
			Protocol:       "TLS",
			Direction:      "egress",
			PID:            ev.PID,
			ProcessName:    ev.ProcessName,
			HTTPMethod:     fields.method,
			URL:            fields.url,
			RequestHeaders: fields.headers,
			BodySnippet:    fields.body,
			RequestBody:    fields.requestBody,
			TLSIntercepted: true,
		}
	}
	fields, ok := parseHTTPResponseFields(data)
	if !ok {
		return nil
	}
	return &types.TrafficEvent{
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
	for key, state := range p.h2Conns {
		if state.updated.Before(cutoff) {
			delete(p.h2Conns, key)
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
		RequestBody:    fields.requestBody,
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
	method      string
	url         string
	headers     map[string]string
	body        string
	requestBody string // full request body up to RequestBodyMaxLen
}

type httpResponseFields struct {
	statusCode int
	headers    map[string]string
	body       string
}

// parseHTTPRequestFields attempts to parse an HTTP/1.1 request from data.
// Returns (nil, false) if the message is incomplete or not HTTP.
//
// Falls back to request-line-only parsing when the header block is truncated
// (common with NSPR's PR_Write where data may exceed MAX_SSL_DATA_SIZE).
func parseHTTPRequestFields(data []byte) (*httpRequestFields, bool) {
	r := bufio.NewReader(bytes.NewReader(data))
	req, err := http.ReadRequest(r)
	if err != nil {
		// Standard parser failed — try the request-line fallback.
		return parseRequestLineFallback(data)
	}
	defer req.Body.Close()

	allBody, _ := io.ReadAll(io.LimitReader(req.Body, int64(types.RequestBodyMaxLen)))
	bodyN := len(allBody)

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
	requestBody := ""
	if bodyN > 0 {
		requestBody = string(allBody)
		snippetN := bodyN
		if snippetN > types.BodySnippetMaxLen {
			snippetN = types.BodySnippetMaxLen
		}
		body = string(allBody[:snippetN])
	}

	return &httpRequestFields{
		method:      req.Method,
		url:         req.URL.String(),
		headers:     headers,
		body:        body,
		requestBody: requestBody,
	}, true
}

// parseRequestLineFallback extracts the HTTP method, URL, and any available
// headers from truncated request data where http.ReadRequest fails because
// the header block is not terminated with \r\n\r\n.
func parseRequestLineFallback(data []byte) (*httpRequestFields, bool) {
	idx := bytes.IndexByte(data, '\n')
	if idx < 0 {
		return nil, false
	}
	line := strings.TrimRight(string(data[:idx]), "\r")
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/") {
		return nil, false
	}
	method := parts[0]
	if !isValidHTTPMethod(method) {
		return nil, false
	}
	url := parts[1]

	// Scan available header lines (may be incomplete).
	headers := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data[idx+1:]))
	for scanner.Scan() {
		hl := scanner.Text()
		if hl == "" {
			break // empty line = end of headers
		}
		if colonIdx := strings.IndexByte(hl, ':'); colonIdx > 0 {
			key := strings.TrimSpace(hl[:colonIdx])
			val := strings.TrimSpace(hl[colonIdx+1:])
			headers[http.CanonicalHeaderKey(key)] = val
		}
	}

	// Extract request body after the \r\n\r\n header terminator.
	var requestBody string
	if sep := bytes.Index(data, []byte("\r\n\r\n")); sep >= 0 {
		bodyData := data[sep+4:]
		if len(bodyData) > types.RequestBodyMaxLen {
			bodyData = bodyData[:types.RequestBodyMaxLen]
		}
		if len(bodyData) > 0 {
			requestBody = string(bodyData)
		}
	}

	return &httpRequestFields{
		method:      method,
		url:         url,
		headers:     headers,
		requestBody: requestBody,
	}, true
}

// isValidHTTPMethod returns true for standard HTTP methods.
func isValidHTTPMethod(m string) bool {
	switch m {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE":
		return true
	}
	return false
}

// parseHTTPResponseFields attempts to parse an HTTP/1.1 response from data.
// Returns (nil, false) if the message is incomplete or not HTTP.
func parseHTTPResponseFields(data []byte) (*httpResponseFields, bool) {
	r := bufio.NewReader(bytes.NewReader(data))
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		// Standard parser failed — try status-line fallback for truncated data.
		return parseResponseLineFallback(data)
	}
	defer resp.Body.Close()

	allBody, _ := io.ReadAll(io.LimitReader(resp.Body, int64(types.BodySnippetMaxLen)))
	bodyN := len(allBody)

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
		if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
			body = decompressGzip(allBody)
		} else {
			body = string(allBody)
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

// parseResponseLineFallback extracts the status code and available headers
// from truncated response data.
func parseResponseLineFallback(data []byte) (*httpResponseFields, bool) {
	idx := bytes.IndexByte(data, '\n')
	if idx < 0 {
		return nil, false
	}
	line := strings.TrimRight(string(data[:idx]), "\r")
	// Status line: "HTTP/1.1 200 OK"
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return nil, false
	}
	code := 0
	fmt.Sscanf(parts[1], "%d", &code)
	if code < 100 || code > 599 {
		return nil, false
	}

	headers := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data[idx+1:]))
	for scanner.Scan() {
		hl := scanner.Text()
		if hl == "" {
			break
		}
		if colonIdx := strings.IndexByte(hl, ':'); colonIdx > 0 {
			key := strings.TrimSpace(hl[:colonIdx])
			val := strings.TrimSpace(hl[colonIdx+1:])
			headers[http.CanonicalHeaderKey(key)] = val
		}
	}

	return &httpResponseFields{
		statusCode: code,
		headers:    headers,
	}, true
}

// ---- Helpers ----

func isClientPort(dstPort uint16) bool {
	return dstPort == 80 || dstPort == 443 || dstPort == 8080 || dstPort == 8443
}

func isServerPort(srcPort uint16) bool {
	return srcPort == 80 || srcPort == 443 || srcPort == 8080 || srcPort == 8443
}

// looksLikeHTTPStart returns true if data could be the beginning of an HTTP
// message. For write (request) data: checks for HTTP method prefix.
// For read (response) data: checks for "HTTP/" prefix.
// This filters out non-HTTP data (IPC, file I/O) from NSPR PR_Write noise.
func looksLikeHTTPStart(data []byte, isRead bool) bool {
	if len(data) < 4 {
		return false
	}
	if isRead {
		return bytes.HasPrefix(data, []byte("HTTP/"))
	}
	// Check for standard HTTP method prefixes.
	switch {
	case bytes.HasPrefix(data, []byte("GET ")),
		bytes.HasPrefix(data, []byte("POST")),
		bytes.HasPrefix(data, []byte("PUT ")),
		bytes.HasPrefix(data, []byte("DELE")),
		bytes.HasPrefix(data, []byte("PATC")),
		bytes.HasPrefix(data, []byte("HEAD")),
		bytes.HasPrefix(data, []byte("OPTI")),
		bytes.HasPrefix(data, []byte("CONN")),
		bytes.HasPrefix(data, []byte("TRAC")):
		return true
	}
	return false
}

func headersToMap(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, vs := range h {
		m[k] = strings.Join(vs, ", ")
	}
	return m
}
