// Package parser performs HTTP/1.1 and HTTP/2 parsing on raw packet payloads
// captured by the TC eBPF program and on plaintext data captured by SSL uprobes.
//
// Architecture:
//
//	RawPacketEvent  →  HandlePacket   →  per-flow buffer / h2c  →  TrafficEvent
//	SSLEvent        →  HandleSSLEvent →  per-flow buffer / H2   →  TrafficEvent
//
// HTTP/1.1 payloads are accumulated in a per-flow (4-tuple) ring until a
// complete message can be parsed.  HTTP/2 connections (both TLS and cleartext
// h2c) are detected from the client preface or mid-connection frame heuristics
// and routed to a shared frame parser with per-connection HPACK decoders.
//
// Limitation: TCP sequence numbers are not captured by the BPF program, so
// out-of-order segment reassembly is not supported. In-order delivery (the
// common case) works correctly.
package parser

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"github.com/traffic-agent/traffic-agent/internal/types"
)

// Debug counters for diagnostics.
var (
	sslEventsReceived  atomic.Int64
	sslEventsH2Preface atomic.Int64
	sslEventsH2Routed  atomic.Int64
	sslEventsH1Path    atomic.Int64
	sslEventsSkipped   atomic.Int64
	sslBodyHits        atomic.Int64 // SSL events with notable HTTP content
	sseStreamsCreated   atomic.Int64
	sseChunksEmitted   atomic.Int64
	wsConnsCreated     atomic.Int64
	wsFramesParsed     atomic.Int64
)

// sslContentPatterns are substrings scanned in raw SSL event data for diagnostics.
// When any pattern is found, a one-time log is emitted to confirm the SSL uprobe
// is capturing relevant data.
var sslContentPatterns = []string{
	"capital", "france", "paris",
	"/api/", "completion", "chat_conversation",
	"text/event-stream", "claude", "anthropic",
	"\"messages\"", "\"content\"", "\"role\"",
}

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

// sslConnKey identifies an SSL connection (direction-independent).
type sslConnKey struct {
	PID    uint32
	ConnID uint64
}

// sslRequestMeta stores the last request metadata per SSL connection,
// enabling request→response correlation for SSE streams.
type sslRequestMeta struct {
	method  string
	url     string
	host    string
	updated time.Time
}

// sseStream tracks an active SSE (text/event-stream) response.
type sseStream struct {
	method          string
	url             string
	host            string
	statusCode      int
	processName     string
	contentEncoding string // gzip, br, zstd, deflate
	compressedBuf   []byte // accumulated compressed data for streaming decompression
	decompOffset    int    // bytes already emitted from decompressed stream
	updated         time.Time
}

// wsConn tracks an active WebSocket connection (post HTTP 101 upgrade).
type wsConn struct {
	url         string
	host        string
	processName string
	deflate     bool // permessage-deflate negotiated
	// Per-direction reassembly for fragmented messages (FIN=0)
	readBuf     []byte // server→client fragments
	writeBuf    []byte // client→server fragments
	readOpcode  byte   // opcode from first fragment
	writeOpcode byte
	updated     time.Time
}

// wsFrame is a parsed WebSocket frame (RFC 6455).
type wsFrame struct {
	fin     bool
	rsv1    bool
	opcode  byte
	payload []byte
}

type flowBuf struct {
	data          []byte
	updated       time.Time
	lastParsedAt  time.Time // set when a complete message was last emitted
}

// Parser accumulates per-flow payloads and emits HTTP traffic events.
type Parser struct {
	sink       EventSink
	mu         sync.Mutex
	bufs       map[flowKey]*flowBuf
	sslBufs    map[sslFlowKey]*flowBuf
	h2Conns    map[h2ConnKey]*h2ConnState // HTTP/2 connection states keyed by (PID,TID,ConnID) or 4-tuple
	h2cFlows   map[flowKey]bool           // TC flows identified as h2c (fast lookup)
	sslReqMeta map[sslConnKey]*sslRequestMeta // last request per SSL conn (for SSE correlation)
	sseStreams map[sslConnKey]*sseStream       // active SSE response streams
	wsConns    map[sslConnKey]*wsConn          // active WebSocket connections
}

// New creates a Parser that will call sink for each parsed HTTP event.
func New(sink EventSink) *Parser {
	return &Parser{
		sink:       sink,
		bufs:       make(map[flowKey]*flowBuf),
		sslBufs:    make(map[sslFlowKey]*flowBuf),
		h2Conns:    make(map[h2ConnKey]*h2ConnState),
		h2cFlows:   make(map[flowKey]bool),
		sslReqMeta: make(map[sslConnKey]*sslRequestMeta),
		sseStreams: make(map[sslConnKey]*sseStream),
		wsConns:    make(map[sslConnKey]*wsConn),
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

	// Fast path: if this flow is already identified as h2c, route directly.
	p.mu.Lock()
	isH2C := p.h2cFlows[key]
	p.mu.Unlock()
	if isH2C {
		p.handleH2CPacket(key, ev)
		return
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

// SSLBodyHits returns the number of SSL events that contained notable HTTP content.
func SSLBodyHits() int64 { return sslBodyHits.Load() }

// H2ConnCount returns the number of tracked H2 connections.
func (p *Parser) H2ConnCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.h2Conns)
}

// HandleSSLEvent appends ev.Data to the per-SSL-stream buffer and attempts to
// parse a complete HTTP/1.1 or HTTP/2 message from the accumulated plaintext.
func (p *Parser) HandleSSLEvent(ev *types.SSLEvent) {
	if len(ev.Data) == 0 {
		return
	}
	sslEventsReceived.Add(1)

	// Diagnostic: scan raw SSL data for notable HTTP content patterns.
	// This confirms the SSL uprobe is capturing relevant data even when
	// the H2 parser fails to produce events.
	if len(ev.Data) > 10 {
		dataStr := string(ev.Data)
		for _, pat := range sslContentPatterns {
			if strings.Contains(strings.ToLower(dataStr), pat) {
				count := sslBodyHits.Add(1)
				if count <= 20 || count%50 == 0 {
					dir := "write"
					if ev.IsRead {
						dir = "read"
					}
					preview := dataStr
					if len(preview) > 200 {
						preview = preview[:200]
					}
					log.Printf("[ssl-content] HIT pat=%q %s pid=%d conn=0x%x len=%d preview=%.200s",
						pat, dir, ev.PID, ev.ConnID, len(ev.Data), preview)
				}
				break // only log once per event
			}
		}
	}

	h2Key := h2ConnKey{PID: ev.PID, ConnID: ev.ConnID}

	// Check whether this PID+ConnID is already tracked as an HTTP/2 connection.
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
		h2State = newH2ConnStateMidJoin()
		p.mu.Lock()
		p.h2Conns[h2Key] = h2State
		p.mu.Unlock()
		sslEventsH2Preface.Add(1)
		log.Printf("[parser] HTTP/2 mid-connection join PID=%d TID=%d conn=0x%x proc=%s (frame type=0x%02x)",
			ev.PID, ev.TID, ev.ConnID, ev.ProcessName, ev.Data[3])
	}

	if h2State != nil {
		sslEventsH2Routed.Add(1)
		meta := &h2EventMeta{
			PID:         ev.PID,
			ProcessName: ev.ProcessName,
			Protocol:    "TLS",
		}
		connKey := h2ConnKey{PID: ev.PID, ConnID: ev.ConnID}
		p.handleH2Event(h2State, ev.Data, ev.IsRead, meta, connKey)
		return
	}

	// ---- WebSocket frame routing ----
	//
	// If this SSL connection has been upgraded to WebSocket (HTTP 101),
	// route all subsequent data through the WebSocket frame parser.
	{
		ck := sslConnKey{PID: ev.PID, ConnID: ev.ConnID}
		p.mu.Lock()
		ws := p.wsConns[ck]
		p.mu.Unlock()
		if ws != nil {
			p.handleWSEvent(ws, ev)
			return
		}
	}

	// ---- SSE stream continuation check ----
	//
	// If this SSL read belongs to an active SSE (text/event-stream) response,
	// emit the raw SSE data as a body-only TrafficEvent with stored metadata.
	// This mirrors how H2 DATA frames are emitted per-chunk with stream info.
	if ev.IsRead {
		ck := sslConnKey{PID: ev.PID, ConnID: ev.ConnID}
		p.mu.Lock()
		sse := p.sseStreams[ck]
		p.mu.Unlock()

		if sse != nil {
			if bytes.HasPrefix(ev.Data, []byte("HTTP/")) {
				// New HTTP response on same connection — SSE stream ended
				// (connection reuse). Delete and fall through to normal parsing.
				p.mu.Lock()
				delete(p.sseStreams, ck)
				p.mu.Unlock()
			} else {
				// Decode the raw SSL_read data: strip chunked TE framing,
				// then decompress using accumulated compressed buffer.
				body := dechunkData(ev.Data)

				p.mu.Lock()
				sse.updated = time.Now()

				if len(body) == 0 {
					// Terminal chunk (0\r\n\r\n) or framing-only data.
					p.mu.Unlock()
					return
				}

				var snippet string
				if sse.contentEncoding != "" && sse.contentEncoding != "identity" {
					// Streaming decompression: accumulate compressed bytes,
					// decompress from start, skip already-emitted bytes.
					const maxCompBuf = 256 * 1024
					if len(sse.compressedBuf)+len(body) <= maxCompBuf {
						sse.compressedBuf = append(sse.compressedBuf, body...)
					}
					snippet = decompressBodyAt(sse.compressedBuf, sse.contentEncoding, sse.decompOffset)
					if snippet != "" && !strings.HasPrefix(snippet, "<") {
						sse.decompOffset += len(snippet)
					}
				} else {
					snippet = string(body)
					if len(snippet) > types.BodySnippetMaxLen {
						snippet = snippet[:types.BodySnippetMaxLen]
					}
				}
				p.mu.Unlock()

				if len(strings.TrimSpace(snippet)) == 0 {
					return
				}

				sseChunksEmitted.Add(1)
				sslEventsH1Path.Add(1)
				p.sink(&types.TrafficEvent{
					Timestamp:      time.Now(),
					Protocol:       "TLS",
					Direction:      "ingress",
					PID:            ev.PID,
					ProcessName:    sse.processName,
					HTTPMethod:     sse.method,
					URL:            sse.url,
					StatusCode:     sse.statusCode,
					BodySnippet:    snippet,
					TLSIntercepted: true,
				})
				return
			}
		}
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
		p.emitSSLEventWithTracking(te, ev)
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
			n := sslEventsSkipped.Add(1)
			// Log first few skipped events for diagnostics.
			if n <= 5 && len(ev.Data) > 20 {
				log.Printf("[ssl-skip] pid=%d conn=0x%x isRead=%v len=%d first8=%x",
					ev.PID, ev.ConnID, ev.IsRead, len(ev.Data), ev.Data[:min(8, len(ev.Data))])
			}
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
		p.emitSSLEventWithTracking(te, ev)
		p.deleteSSLBuf(key)
	}
}

// emitSSLEventWithTracking sinks the TrafficEvent and updates SSE tracking:
//   - For writes (requests): stores method/URL/host for request→response correlation.
//   - For reads (responses): if Content-Type is text/event-stream, registers an
//     SSE stream so subsequent SSL_reads emit chunks with the stored metadata.
func (p *Parser) emitSSLEventWithTracking(te *types.TrafficEvent, ev *types.SSLEvent) {
	ck := sslConnKey{PID: ev.PID, ConnID: ev.ConnID}

	if !ev.IsRead && te.HTTPMethod != "" {
		// Track the most recent request on this SSL connection.
		p.mu.Lock()
		p.sslReqMeta[ck] = &sslRequestMeta{
			method:  te.HTTPMethod,
			url:     te.URL,
			host:    te.RequestHeaders["Host"],
			updated: time.Now(),
		}
		p.mu.Unlock()
	}

	if ev.IsRead && te.StatusCode == 101 {
		// Check if this response is a WebSocket upgrade.
		upgrade := strings.ToLower(te.ResponseHeaders["Upgrade"])
		if upgrade == "websocket" {
			p.mu.Lock()
			extensions := te.ResponseHeaders["Sec-Websocket-Extensions"]
			ws := &wsConn{
				processName: ev.ProcessName,
				deflate:     strings.Contains(strings.ToLower(extensions), "permessage-deflate"),
				updated:     time.Now(),
			}
			if reqMeta := p.sslReqMeta[ck]; reqMeta != nil {
				ws.url = reqMeta.url
				ws.host = reqMeta.host
			}
			p.wsConns[ck] = ws
			p.mu.Unlock()
			wsConnsCreated.Add(1)
			log.Printf("[ws] connection established pid=%d conn=0x%x url=%s deflate=%v",
				ev.PID, ev.ConnID, ws.url, ws.deflate)
		}
	}

	if ev.IsRead && te.StatusCode > 0 {
		// Check if this response starts an SSE stream.
		ct := te.ResponseHeaders["Content-Type"]
		if strings.Contains(strings.ToLower(ct), "text/event-stream") {
			p.mu.Lock()
			reqMeta := p.sslReqMeta[ck]
			ce := strings.ToLower(strings.TrimSpace(te.ResponseHeaders["Content-Encoding"]))
			sse := &sseStream{
				statusCode:      te.StatusCode,
				processName:     ev.ProcessName,
				contentEncoding: ce,
				updated:         time.Now(),
			}
			// Seed the compressed buffer from the initial SSL_read's raw body.
			// The raw data has HTTP headers followed by the body (possibly
			// chunked + compressed). Extract body after \r\n\r\n and dechunk.
			if ce != "" && ce != "identity" {
				if sep := bytes.Index(ev.Data, []byte("\r\n\r\n")); sep >= 0 {
					rawBody := ev.Data[sep+4:]
					sse.compressedBuf = dechunkData(rawBody)
					// The initial response's body was already decompressed
					// by http.ReadResponse, so set decompOffset to skip it.
					if len(te.BodySnippet) > 0 {
						sse.decompOffset = len(te.BodySnippet)
					}
				}
			}
			if reqMeta != nil {
				sse.method = reqMeta.method
				sse.url = reqMeta.url
				sse.host = reqMeta.host
				// Enrich the initial response event with request metadata.
				te.HTTPMethod = reqMeta.method
				te.URL = reqMeta.url
			}
			p.sseStreams[ck] = sse
			p.mu.Unlock()
			sseStreamsCreated.Add(1)
			log.Printf("[sse] stream started pid=%d conn=0x%x method=%s url=%s status=%d",
				ev.PID, ev.ConnID, sse.method, sse.url, sse.statusCode)
		}
	}

	p.sink(te)
}

// SSEStreamStats returns SSE diagnostic counters.
func SSEStreamStats() (streams, chunks int64) {
	return sseStreamsCreated.Load(), sseChunksEmitted.Load()
}

// WSStats returns WebSocket diagnostic counters.
func WSStats() (conns, frames int64) {
	return wsConnsCreated.Load(), wsFramesParsed.Load()
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

// FlushExpired removes stale flow buffers and H2 connection states that have
// been idle longer than their respective timeouts.
//   - flowTimeout applies to HTTP/1.1 accumulation buffers (bufs, sslBufs)
//   - h2Timeout applies to persistent HTTP/2 connection states (h2Conns)
//
// H2 connections are long-lived (browsers keep them open for minutes/hours),
// so h2Timeout should be much longer than flowTimeout to avoid losing HPACK
// state for idle-but-alive connections.
func (p *Parser) FlushExpired(flowTimeout, h2Timeout time.Duration) {
	now := time.Now()
	flowCutoff := now.Add(-flowTimeout)
	h2Cutoff := now.Add(-h2Timeout)

	p.mu.Lock()
	defer p.mu.Unlock()
	for key, fb := range p.bufs {
		if fb.updated.Before(flowCutoff) {
			delete(p.bufs, key)
		}
	}
	for key, fb := range p.sslBufs {
		if fb.updated.Before(flowCutoff) {
			delete(p.sslBufs, key)
		}
	}
	for key, rm := range p.sslReqMeta {
		if rm.updated.Before(flowCutoff) {
			delete(p.sslReqMeta, key)
		}
	}
	for key, sse := range p.sseStreams {
		if sse.updated.Before(flowCutoff) {
			delete(p.sseStreams, key)
		}
	}
	for key, ws := range p.wsConns {
		if ws.updated.Before(flowCutoff) {
			delete(p.wsConns, key)
		}
	}
	h2Expired := 0
	for key, state := range p.h2Conns {
		if state.updated.Before(h2Cutoff) {
			delete(p.h2Conns, key)
			h2Expired++
			// If this is an h2c connection (has network fields), clean up h2cFlows.
			if key.SrcIP != "" {
				fwd := flowKey{srcIP: key.SrcIP, dstIP: key.DstIP, srcPort: key.SrcPort, dstPort: key.DstPort}
				rev := flowKey{srcIP: key.DstIP, dstIP: key.SrcIP, srcPort: key.DstPort, dstPort: key.SrcPort}
				delete(p.h2cFlows, fwd)
				delete(p.h2cFlows, rev)
			}
		}
	}
	if h2Expired > 0 {
		h2StatesExpired.Add(int64(h2Expired))
		log.Printf("[parser] FlushExpired: removed %d H2 connection state(s), %d remaining", h2Expired, len(p.h2Conns))
	}
}

// ---- Internal parse helpers (TC packet events) ----

func (p *Parser) tryParseRequest(key flowKey, data []byte, ev *types.RawPacketEvent) {
	// HTTP/2 cleartext (h2c) connection preface detection.
	if bytes.HasPrefix(data, []byte("PRI * HTTP/2.0")) {
		p.initH2CConnection(key, data, ev)
		return
	}

	fields, ok := parseHTTPRequestFields(data)
	if !ok {
		// HTTP/1.1 parse failed — check for mid-connection h2c frames.
		if looksLikeH2MidConnection(data) {
			p.initH2CMidConnection(key, data, ev)
		}
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
		// HTTP/1.1 parse failed — check for mid-connection h2c frames.
		if looksLikeH2MidConnection(data) {
			p.initH2CMidConnection(key, data, ev)
		}
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

// ---- h2c (HTTP/2 cleartext) helpers ----

// handleH2CPacket routes a TC packet for an already-identified h2c flow to
// the HTTP/2 frame parser.
func (p *Parser) handleH2CPacket(key flowKey, ev *types.RawPacketEvent) {
	isRead := isServerPort(ev.SrcPort)
	connKey := h2cConnKey(ev)

	meta := &h2EventMeta{
		PID:         ev.PID,
		ProcessName: ev.ProcessName,
		SrcIP:       connKey.SrcIP,
		DstIP:       connKey.DstIP,
		SrcPort:     connKey.SrcPort,
		DstPort:     connKey.DstPort,
		Protocol:    "TCP",
	}

	p.mu.Lock()
	state := p.h2Conns[connKey]
	if state == nil {
		state = newH2ConnState()
		p.h2Conns[connKey] = state
	}
	p.mu.Unlock()

	p.handleH2Event(state, ev.Payload, isRead, meta, connKey)
}

// h2cConnKey builds a normalized h2ConnKey from a TC packet event with the
// server-side address consistently in DstIP:DstPort.
func h2cConnKey(ev *types.RawPacketEvent) h2ConnKey {
	if isServerPort(ev.SrcPort) {
		// Server is source — flip so server ends up in Dst.
		return h2ConnKey{
			SrcIP:   ev.DstIP.String(),
			DstIP:   ev.SrcIP.String(),
			SrcPort: ev.DstPort,
			DstPort: ev.SrcPort,
		}
	}
	return h2ConnKey{
		SrcIP:   ev.SrcIP.String(),
		DstIP:   ev.DstIP.String(),
		SrcPort: ev.SrcPort,
		DstPort: ev.DstPort,
	}
}

// initH2CConnection initializes h2c tracking when a connection preface is detected.
func (p *Parser) initH2CConnection(key flowKey, data []byte, ev *types.RawPacketEvent) {
	connKey := h2cConnKey(ev)

	p.mu.Lock()
	// Mark both forward and reverse flows as h2c.
	p.h2cFlows[key] = true
	reverseKey := flowKey{
		srcIP:   key.dstIP,
		dstIP:   key.srcIP,
		srcPort: key.dstPort,
		dstPort: key.srcPort,
	}
	p.h2cFlows[reverseKey] = true

	state := newH2ConnState()
	p.h2Conns[connKey] = state
	delete(p.bufs, key)
	p.mu.Unlock()

	h2cConnectionsDetected.Add(1)
	log.Printf("[parser] h2c connection detected: %s:%d -> %s:%d",
		ev.SrcIP, ev.SrcPort, ev.DstIP, ev.DstPort)

	// Feed the full data (including preface) to handleH2Event — the write
	// path strips the preface automatically.
	isRead := isServerPort(ev.SrcPort)
	meta := &h2EventMeta{
		PID:         ev.PID,
		ProcessName: ev.ProcessName,
		SrcIP:       connKey.SrcIP,
		DstIP:       connKey.DstIP,
		SrcPort:     connKey.SrcPort,
		DstPort:     connKey.DstPort,
		Protocol:    "TCP",
	}
	p.handleH2Event(state, data, isRead, meta, connKey)
}

// initH2CMidConnection initializes h2c tracking when mid-connection HTTP/2
// frames are detected (agent started after the h2c connection was opened).
func (p *Parser) initH2CMidConnection(key flowKey, data []byte, ev *types.RawPacketEvent) {
	connKey := h2cConnKey(ev)

	p.mu.Lock()
	if _, exists := p.h2Conns[connKey]; exists {
		p.mu.Unlock()
		return // already tracked
	}

	p.h2cFlows[key] = true
	reverseKey := flowKey{
		srcIP:   key.dstIP,
		dstIP:   key.srcIP,
		srcPort: key.dstPort,
		dstPort: key.srcPort,
	}
	p.h2cFlows[reverseKey] = true

	state := newH2ConnStateMidJoin()
	p.h2Conns[connKey] = state
	delete(p.bufs, key)
	p.mu.Unlock()

	h2cConnectionsDetected.Add(1)
	log.Printf("[parser] h2c mid-connection detected: %s:%d -> %s:%d (frame type=0x%02x)",
		ev.SrcIP, ev.SrcPort, ev.DstIP, ev.DstPort, data[3])

	isRead := isServerPort(ev.SrcPort)
	meta := &h2EventMeta{
		PID:         ev.PID,
		ProcessName: ev.ProcessName,
		SrcIP:       connKey.SrcIP,
		DstIP:       connKey.DstIP,
		SrcPort:     connKey.SrcPort,
		DstPort:     connKey.DstPort,
		Protocol:    "TCP",
	}
	p.handleH2Event(state, data, isRead, meta, connKey)
}

// ---- WebSocket frame handling ----

// handleWSEvent processes SSL data on a WebSocket connection.  It parses
// RFC 6455 frames, handles XOR unmasking, permessage-deflate decompression,
// and fragment reassembly, emitting a TrafficEvent for each complete text
// or binary message.
func (p *Parser) handleWSEvent(ws *wsConn, ev *types.SSLEvent) {
	// Client→server frames are masked (MASK=1); server→client are not.
	masked := !ev.IsRead
	frames := parseWSFrames(ev.Data, masked)

	p.mu.Lock()
	ws.updated = time.Now()
	p.mu.Unlock()

	for _, f := range frames {
		// Skip control frames (close=8, ping=9, pong=10).
		if f.opcode >= 8 {
			continue
		}
		wsFramesParsed.Add(1)

		// Fragment reassembly: opcode 0 = continuation frame.
		p.mu.Lock()
		if f.opcode == 0 {
			// Continuation of a fragmented message.
			if ev.IsRead {
				ws.readBuf = append(ws.readBuf, f.payload...)
				if f.fin {
					f.payload = ws.readBuf
					f.opcode = ws.readOpcode
					f.rsv1 = false // RSV1 only set on first fragment
					ws.readBuf = nil
				} else {
					p.mu.Unlock()
					continue
				}
			} else {
				ws.writeBuf = append(ws.writeBuf, f.payload...)
				if f.fin {
					f.payload = ws.writeBuf
					f.opcode = ws.writeOpcode
					f.rsv1 = false
					ws.writeBuf = nil
				} else {
					p.mu.Unlock()
					continue
				}
			}
		} else if !f.fin {
			// First fragment of a multi-frame message.
			if ev.IsRead {
				ws.readBuf = append(ws.readBuf[:0], f.payload...)
				ws.readOpcode = f.opcode
			} else {
				ws.writeBuf = append(ws.writeBuf[:0], f.payload...)
				ws.writeOpcode = f.opcode
			}
			p.mu.Unlock()
			continue
		}
		deflate := ws.deflate
		p.mu.Unlock()

		payload := f.payload

		// permessage-deflate: RSV1=1 means the message is DEFLATE-compressed.
		// With no_context_takeover, each message is independently compressed.
		if f.rsv1 && deflate {
			// Append the DEFLATE flush marker (RFC 7692 §7.2.2).
			compressed := make([]byte, len(payload)+4)
			copy(compressed, payload)
			compressed[len(payload)] = 0x00
			compressed[len(payload)+1] = 0x00
			compressed[len(payload)+2] = 0xff
			compressed[len(payload)+3] = 0xff
			fr := flate.NewReader(bytes.NewReader(compressed))
			decompressed, err := io.ReadAll(io.LimitReader(fr, int64(types.RequestBodyMaxLen)))
			fr.Close()
			if err != nil && len(decompressed) == 0 {
				log.Printf("[ws] deflate error pid=%d conn=0x%x: %v", ev.PID, ev.ConnID, err)
				continue
			}
			payload = decompressed
		}

		// Only emit text (opcode=1) and binary (opcode=2) messages.
		if f.opcode != 1 && f.opcode != 2 {
			continue
		}

		direction := "ingress"
		if !ev.IsRead {
			direction = "egress"
		}

		snippet := string(payload)
		if len(snippet) > types.BodySnippetMaxLen {
			snippet = snippet[:types.BodySnippetMaxLen]
		}

		p.sink(&types.TrafficEvent{
			Timestamp:      time.Now(),
			Protocol:       "TLS",
			Direction:      direction,
			PID:            ev.PID,
			ProcessName:    ws.processName,
			HTTPMethod:     "WS",
			URL:            ws.url,
			BodySnippet:    snippet,
			TLSIntercepted: true,
		})
	}
}

// parseWSFrames parses one or more RFC 6455 WebSocket frames from data.
// If masked is true, payloads are XOR-unmasked. Incomplete trailing frames
// are silently dropped (in practice SSL records align with WS frames).
func parseWSFrames(data []byte, masked bool) []wsFrame {
	var frames []wsFrame
	for len(data) >= 2 {
		b0 := data[0]
		b1 := data[1]
		fin := b0&0x80 != 0
		rsv1 := b0&0x40 != 0
		opcode := b0 & 0x0F
		hasMask := b1&0x80 != 0
		payloadLen := uint64(b1 & 0x7F)
		off := 2

		if payloadLen == 126 {
			if len(data) < off+2 {
				break
			}
			payloadLen = uint64(binary.BigEndian.Uint16(data[off : off+2]))
			off += 2
		} else if payloadLen == 127 {
			if len(data) < off+8 {
				break
			}
			payloadLen = binary.BigEndian.Uint64(data[off : off+8])
			off += 8
		}

		var maskKey [4]byte
		if hasMask {
			if len(data) < off+4 {
				break
			}
			copy(maskKey[:], data[off:off+4])
			off += 4
		}

		if uint64(len(data)-off) < payloadLen {
			break // incomplete frame
		}

		payload := make([]byte, payloadLen)
		copy(payload, data[off:off+int(payloadLen)])

		// XOR unmask if needed. The actual mask bit in the frame takes
		// precedence over the caller's hint (client frames should be masked
		// per spec, but we handle both directions).
		if hasMask {
			for i := range payload {
				payload[i] ^= maskKey[i%4]
			}
		}

		frames = append(frames, wsFrame{
			fin:     fin,
			rsv1:    rsv1,
			opcode:  opcode,
			payload: payload,
		})
		off += int(payloadLen)
		data = data[off:]
	}
	return frames
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
		body = decompressBody(allBody, resp.Header.Get("Content-Encoding"))
	}

	return &httpResponseFields{
		statusCode: resp.StatusCode,
		headers:    headersToMap(resp.Header),
		body:       body,
	}, true
}

// dechunkData strips HTTP chunked Transfer-Encoding framing from data.
// Input: "<hex-size>\r\n<data>\r\n[<hex-size>\r\n<data>\r\n]..."
// Returns the concatenated payload with chunk framing removed.
// If the data doesn't look chunked, returns it as-is.
func dechunkData(data []byte) []byte {
	// Quick check: chunked data starts with hex digits followed by \r\n.
	crlfIdx := bytes.Index(data, []byte("\r\n"))
	if crlfIdx <= 0 || crlfIdx > 8 {
		return data // doesn't look chunked
	}
	// Parse the hex size.
	sizeStr := strings.TrimSpace(string(data[:crlfIdx]))
	var chunkSize int
	if _, err := fmt.Sscanf(sizeStr, "%x", &chunkSize); err != nil {
		return data // not a valid chunk header
	}
	if chunkSize == 0 {
		return nil // terminal chunk
	}
	start := crlfIdx + 2
	if start+chunkSize > len(data) {
		// Chunk extends beyond data — take what we have.
		return data[start:]
	}
	// Collect this chunk's payload, then try to parse more chunks.
	var result []byte
	result = append(result, data[start:start+chunkSize]...)
	rest := data[start+chunkSize:]
	// Skip trailing \r\n after chunk data.
	if len(rest) >= 2 && rest[0] == '\r' && rest[1] == '\n' {
		rest = rest[2:]
	}
	// Recursively parse remaining chunks (typically 0-2 more in an SSL record).
	if len(rest) > 0 {
		more := dechunkData(rest)
		if more != nil {
			result = append(result, more...)
		}
	}
	return result
}

// decompressBody attempts to decompress data according to the given
// Content-Encoding value. Supports gzip, br (Brotli), zstd, and deflate.
// Returns the original data as a string if encoding is empty or unknown,
// or a placeholder if decompression fails.
func decompressBody(data []byte, encoding string) string {
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	if encoding == "" || encoding == "identity" {
		return string(data)
	}

	var reader io.Reader
	switch encoding {
	case "gzip":
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return "<gzip-error>"
		}
		defer gr.Close()
		reader = gr
	case "br":
		reader = brotli.NewReader(bytes.NewReader(data))
	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			return "<zstd-error>"
		}
		defer zr.Close()
		reader = zr
	case "deflate":
		fr := flate.NewReader(bytes.NewReader(data))
		defer fr.Close()
		reader = fr
	default:
		return string(data)
	}

	out := make([]byte, types.BodySnippetMaxLen)
	n, err := io.ReadAtLeast(reader, out, 1)
	if err != nil && n == 0 {
		return fmt.Sprintf("<%s-compressed>", encoding)
	}
	return string(out[:n])
}

// decompressBodyAt decompresses accumulated data starting at a byte offset
// into the decompressed output.  This allows incremental decompression across
// multiple HTTP/2 DATA frames — each call skips already-emitted bytes and
// returns only NEW decompressed content (up to BodySnippetMaxLen).
func decompressBodyAt(data []byte, encoding string, offset int) string {
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	if encoding == "" || encoding == "identity" {
		if offset >= len(data) {
			return ""
		}
		end := offset + types.BodySnippetMaxLen
		if end > len(data) {
			end = len(data)
		}
		return string(data[offset:end])
	}

	var reader io.Reader
	switch encoding {
	case "gzip":
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return ""
		}
		defer gr.Close()
		reader = gr
	case "br":
		reader = brotli.NewReader(bytes.NewReader(data))
	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			return ""
		}
		defer zr.Close()
		reader = zr
	case "deflate":
		fr := flate.NewReader(bytes.NewReader(data))
		defer fr.Close()
		reader = fr
	default:
		return ""
	}

	// Skip past already-emitted decompressed bytes.
	if offset > 0 {
		skipped, err := io.CopyN(io.Discard, reader, int64(offset))
		if err != nil || int(skipped) < offset {
			return ""
		}
	}

	// Read new decompressed content.
	out := make([]byte, types.BodySnippetMaxLen)
	n, err := io.ReadAtLeast(reader, out, 1)
	if err != nil && n == 0 {
		return ""
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
