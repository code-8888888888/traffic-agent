// HTTP/3 frame parsing and TrafficEvent emission.
//
// HTTP/3 runs over QUIC streams. Each client-initiated bidirectional stream
// (IDs 0, 4, 8, ...) carries one HTTP request/response exchange.
//
// HTTP/3 frames use QUIC variable-length encoding for type and length:
//   0x00 DATA      — response/request body
//   0x01 HEADERS   — QPACK-encoded header block
//   0x04 SETTINGS  — connection settings (on control stream)
//   0x07 GOAWAY    — graceful shutdown
//
// QPACK decoding uses the static table only (no dynamic table for passive
// interception), matching the existing HPACK approach in http2.go.

package parser

import (
	"encoding/binary"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/traffic-agent/traffic-agent/internal/types"
)

var h3Debug = false // set to true for verbose H3 frame debug logging

func firstN(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}

// HTTP/3 frame types.
const (
	h3FrameData     = uint64(0x00)
	h3FrameHeaders  = uint64(0x01)
	h3FrameSettings = uint64(0x04)
	h3FrameGoaway   = uint64(0x07)
)

// isH3BidiRequestStream returns true if the stream ID is a client-initiated
// bidirectional stream (IDs 0, 4, 8, ...) which carry HTTP request/response
// exchanges. Unidirectional streams (control, QPACK encoder/decoder) and
// server-initiated streams should not have HEADERS/DATA processed.
func isH3BidiRequestStream(streamID uint64) bool {
	return streamID&0x3 == 0x0
}

// h3StreamInfo tracks request metadata for correlating DATA frames with HEADERS.
type h3StreamInfo struct {
	method          string
	path            string
	host            string
	statusCode      int
	contentEncoding string
	gotRequest      bool
	gotResponse     bool
}

// h3StreamBufKey identifies a stream+direction for H3 frame buffering.
type h3StreamBufKey struct {
	streamID uint64
	isServer bool
}

// h3ConnState holds per-connection HTTP/3 state.
type h3ConnState struct {
	activeStreams map[uint64]*h3StreamInfo
	// Per-stream+direction reassembly buffers for partial HTTP/3 frames.
	// Client and server send on independent offset spaces, so their data
	// must be buffered separately even for the same stream ID.
	streamBufs map[h3StreamBufKey][]byte
	updated    time.Time
}

// H3Parser handles HTTP/3 stream data and emits TrafficEvents.
type H3Parser struct {
	mu    sync.Mutex
	conns map[h3ConnKey]*h3ConnState
	sink  EventSink
}

// h3ConnKey identifies an HTTP/3 connection by 5-tuple + PID.
type h3ConnKey struct {
	pid     uint32
	srcIP   string
	dstIP   string
	srcPort uint16
	dstPort uint16
}

// NewH3Parser creates an HTTP/3 parser.
func NewH3Parser(sink EventSink) *H3Parser {
	return &H3Parser{
		conns: make(map[h3ConnKey]*h3ConnState),
		sink:  sink,
	}
}

// HandleStreamData processes reassembled QUIC stream data.
// Called by the QUIC processor's stream assembler callback.
func (p *H3Parser) HandleStreamData(pid uint32, processName string, streamID uint64, isServer bool, data []byte, fin bool,
	srcIP, dstIP string, srcPort, dstPort uint16) {

	if len(data) == 0 {
		return
	}

	key := h3ConnKey{
		pid:     pid,
		srcIP:   srcIP,
		dstIP:   dstIP,
		srcPort: srcPort,
		dstPort: dstPort,
	}

	p.mu.Lock()
	state, ok := p.conns[key]
	if !ok {
		state = &h3ConnState{
			activeStreams: make(map[uint64]*h3StreamInfo),
			streamBufs:   make(map[h3StreamBufKey][]byte),
		}
		p.conns[key] = state
		log.Printf("[h3] new connection state: pid=%d %s:%d→%s:%d", pid, srcIP, srcPort, dstIP, dstPort)
	}
	state.updated = time.Now()

	// Accumulate data in per-stream+direction buffer.
	bufKey := h3StreamBufKey{streamID: streamID, isServer: isServer}
	buf := state.streamBufs[bufKey]
	if len(buf)+len(data) <= maxFlowBufSize {
		buf = append(buf, data...)
	}
	state.streamBufs[bufKey] = buf

	if h3Debug {
		dir := "C"
		if isServer {
			dir = "S"
		}
		log.Printf("[h3] stream=%d/%s len=%d buf=%d fin=%v first_bytes=%x",
			streamID, dir, len(data), len(buf), fin, firstN(buf, 16))
	}

	// Parse as many complete HTTP/3 frames as possible.
	var pending []*types.TrafficEvent
	consumed := p.parseH3Frames(state, streamID, isServer, buf, pid, processName,
		srcIP, dstIP, srcPort, dstPort,
		func(te *types.TrafficEvent) { pending = append(pending, te) })

	if h3Debug && consumed > 0 {
		log.Printf("[h3] stream=%d/%s consumed=%d events=%d",
			streamID, map[bool]string{true: "S", false: "C"}[isServer], consumed, len(pending))
	}

	if consumed > 0 {
		state.streamBufs[bufKey] = buf[consumed:]
	}
	if fin {
		remaining := state.streamBufs[bufKey]
		if len(remaining) > 0 && isH3BidiRequestStream(streamID) {
			log.Printf("[h3-WARN] stream=%d/%s FIN with %d unconsumed bytes (incomplete H3 frame) first_bytes=%x srcPort=%d",
				streamID, map[bool]string{true: "S", false: "C"}[isServer], len(remaining), firstN(remaining, 32), srcPort)
		}
		delete(state.streamBufs, bufKey)
	}

	p.mu.Unlock()

	for _, te := range pending {
		p.sink(te)
	}
}

// parseH3Frames parses HTTP/3 frames from a stream buffer.
// Returns bytes consumed.
func (p *H3Parser) parseH3Frames(state *h3ConnState, streamID uint64, isServer bool, data []byte,
	pid uint32, processName, srcIP, dstIP string, srcPort, dstPort uint16,
	emit func(*types.TrafficEvent)) int {

	consumed := 0
	for len(data) > 0 {
		// Read frame type (varint).
		frameType, n, err := h3DecodeVarint(data)
		if err != nil {
			break
		}
		// Read frame length (varint).
		if n >= len(data) {
			break
		}
		frameLen, m, err := h3DecodeVarint(data[n:])
		if err != nil {
			break
		}
		headerLen := n + m
		totalLen := headerLen + int(frameLen)
		if totalLen > len(data) {
			break // incomplete frame
		}

		payload := data[headerLen:totalLen]

		switch frameType {
		case h3FrameHeaders:
			// Only process HEADERS on client-initiated bidirectional streams.
			// Unidirectional streams (control, QPACK) don't carry request/response data.
			if isH3BidiRequestStream(streamID) {
				p.processH3Headers(state, streamID, isServer, payload, pid, processName,
					srcIP, dstIP, srcPort, dstPort, emit)
			}
		case h3FrameData:
			if isH3BidiRequestStream(streamID) {
				p.processH3Data(state, streamID, isServer, payload, pid, processName,
					srcIP, dstIP, srcPort, dstPort, emit)
			}
		case h3FrameSettings:
			// Settings on control stream — ignore for now.
		case h3FrameGoaway:
			// Connection shutting down.
		}

		consumed += totalLen
		data = data[totalLen:]
	}
	return consumed
}

// processH3Headers QPACK-decodes a HEADERS frame and emits a TrafficEvent.
func (p *H3Parser) processH3Headers(state *h3ConnState, streamID uint64, isServer bool, payload []byte,
	pid uint32, processName, srcIP, dstIP string, srcPort, dstPort uint16,
	emit func(*types.TrafficEvent)) {

	fields := qpackDecode(payload)
	if h3Debug {
		log.Printf("[h3-debug] HEADERS stream=%d isServer=%v payloadLen=%d decodedFields=%d payload[:32]=%x",
			streamID, isServer, len(payload), len(fields), firstN(payload, 32))
		for i, f := range fields {
			log.Printf("[h3-debug]   field[%d] name=%q value=%.80q", i, f.Name, f.Value)
		}
	}
	if len(fields) == 0 {
		if len(payload) > 0 {
			log.Printf("[h3-debug] QPACK decode returned 0 fields for %d bytes: %x", len(payload), firstN(payload, 48))
		}
		return
	}

	// Determine if this is a request or response based on pseudo-headers.
	method, path, authority, status := "", "", "", ""
	headers := make(map[string]string)
	contentEncoding := ""

	for _, f := range fields {
		switch f.Name {
		case ":method":
			method = f.Value
		case ":path":
			path = f.Value
		case ":authority":
			authority = f.Value
		case ":status":
			status = f.Value
		case ":scheme":
			// skip
		default:
			if !strings.HasPrefix(f.Name, ":") {
				headers[http.CanonicalHeaderKey(f.Name)] = f.Value
				if strings.EqualFold(f.Name, "content-encoding") {
					contentEncoding = f.Value
				}
			}
		}
	}

	if method != "" {
		// Request HEADERS.
		if authority != "" {
			headers["Host"] = authority
		}

		info := &h3StreamInfo{
			method:     method,
			path:       path,
			host:       authority,
			gotRequest: true,
		}
		state.activeStreams[streamID] = info

		// Cap active streams.
		if len(state.activeStreams) > 128 {
			for id := range state.activeStreams {
				delete(state.activeStreams, id)
				if len(state.activeStreams) <= 96 {
					break
				}
			}
		}

		emit(&types.TrafficEvent{
			Timestamp:      time.Now(),
			SrcIP:          srcIP,
			DstIP:          dstIP,
			SrcPort:        srcPort,
			DstPort:        dstPort,
			Protocol:       "QUIC",
			Direction:      "egress",
			PID:            pid,
			ProcessName:    processName,
			HTTPMethod:     method,
			URL:            path,
			RequestHeaders: headers,
			TLSIntercepted: true,
		})
	} else if status != "" {
		// Response HEADERS.
		statusCode, _ := strconv.Atoi(status)

		info := state.activeStreams[streamID]
		if info != nil {
			info.statusCode = statusCode
			info.contentEncoding = contentEncoding
			info.gotResponse = true
		}

		// Swap src/dst: callback always passes canonical (client→server),
		// but response flows server→client.
		te := &types.TrafficEvent{
			Timestamp:       time.Now(),
			SrcIP:           dstIP,
			DstIP:           srcIP,
			SrcPort:         dstPort,
			DstPort:         srcPort,
			Protocol:        "QUIC",
			Direction:       "ingress",
			PID:             pid,
			ProcessName:     processName,
			StatusCode:      statusCode,
			ResponseHeaders: headers,
			TLSIntercepted:  true,
		}
		if info != nil {
			te.HTTPMethod = info.method
			te.URL = info.path
		}
		emit(te)
	}
}

// processH3Data handles a DATA frame.
func (p *H3Parser) processH3Data(state *h3ConnState, streamID uint64, isServer bool, payload []byte,
	pid uint32, processName, srcIP, dstIP string, srcPort, dstPort uint16,
	emit func(*types.TrafficEvent)) {

	if len(payload) == 0 {
		return
	}

	info := state.activeStreams[streamID]

	snippet := payload
	if len(snippet) > types.BodySnippetMaxLen {
		snippet = snippet[:types.BodySnippetMaxLen]
	}

	// Full request body (up to RequestBodyMaxLen).
	reqBody := payload
	if len(reqBody) > types.RequestBodyMaxLen {
		reqBody = reqBody[:types.RequestBodyMaxLen]
	}

	snippetStr := string(snippet)
	if info != nil && strings.EqualFold(info.contentEncoding, "gzip") {
		snippetStr = decompressGzip(snippet)
	}

	// Determine direction from isServer flag (provided by QUIC stream assembler).
	evSrcIP, evDstIP := srcIP, dstIP
	evSrcPort, evDstPort := srcPort, dstPort
	direction := "egress"
	if isServer {
		evSrcIP, evDstIP = dstIP, srcIP
		evSrcPort, evDstPort = dstPort, srcPort
		direction = "ingress"
	}

	te := &types.TrafficEvent{
		Timestamp:      time.Now(),
		SrcIP:          evSrcIP,
		DstIP:          evDstIP,
		SrcPort:        evSrcPort,
		DstPort:        evDstPort,
		Protocol:       "QUIC",
		Direction:      direction,
		PID:            pid,
		ProcessName:    processName,
		BodySnippet:    snippetStr,
		TLSIntercepted: true,
	}
	if !isServer {
		te.RequestBody = string(reqBody)
	}
	if info != nil {
		te.HTTPMethod = info.method
		te.URL = info.path
		te.StatusCode = info.statusCode
	}
	emit(te)
}

// FlushExpired removes stale H3 connection states.
func (p *H3Parser) FlushExpired(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, state := range p.conns {
		if state.updated.Before(cutoff) {
			delete(p.conns, key)
		}
	}
}

// h3DecodeVarint decodes a QUIC/HTTP3 variable-length integer.
func h3DecodeVarint(data []byte) (uint64, int, error) {
	if len(data) < 1 {
		return 0, 0, errShortVarint
	}
	prefix := data[0] >> 6
	length := 1 << prefix
	if len(data) < length {
		return 0, 0, errShortVarint
	}

	var val uint64
	switch length {
	case 1:
		val = uint64(data[0] & 0x3F)
	case 2:
		val = uint64(binary.BigEndian.Uint16(data[:2])) & 0x3FFF
	case 4:
		val = uint64(binary.BigEndian.Uint32(data[:4])) & 0x3FFFFFFF
	case 8:
		val = binary.BigEndian.Uint64(data[:8]) & 0x3FFFFFFFFFFFFFFF
	}
	return val, length, nil
}

var errShortVarint = &shortVarintError{}

type shortVarintError struct{}

func (e *shortVarintError) Error() string { return "varint: short data" }
