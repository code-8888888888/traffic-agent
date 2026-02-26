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
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/qpack"

	"github.com/traffic-agent/traffic-agent/internal/types"
)

// HTTP/3 frame types.
const (
	h3FrameData     = uint64(0x00)
	h3FrameHeaders  = uint64(0x01)
	h3FrameSettings = uint64(0x04)
	h3FrameGoaway   = uint64(0x07)
)

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

// h3ConnState holds per-connection HTTP/3 state.
type h3ConnState struct {
	qpackDecoder  *qpack.Decoder
	activeStreams map[uint64]*h3StreamInfo
	// Per-stream reassembly buffers for partial HTTP/3 frames.
	streamBufs map[uint64][]byte
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
func (p *H3Parser) HandleStreamData(pid uint32, processName string, streamID uint64, data []byte, fin bool,
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
			qpackDecoder:  qpack.NewDecoder(),
			activeStreams: make(map[uint64]*h3StreamInfo),
			streamBufs:   make(map[uint64][]byte),
		}
		p.conns[key] = state
	}
	state.updated = time.Now()

	// Accumulate data in per-stream buffer.
	buf := state.streamBufs[streamID]
	if len(buf)+len(data) <= maxFlowBufSize {
		buf = append(buf, data...)
	}
	state.streamBufs[streamID] = buf

	// Parse as many complete HTTP/3 frames as possible.
	var pending []*types.TrafficEvent
	consumed := p.parseH3Frames(state, streamID, buf, pid, processName,
		srcIP, dstIP, srcPort, dstPort,
		func(te *types.TrafficEvent) { pending = append(pending, te) })

	if consumed > 0 {
		state.streamBufs[streamID] = buf[consumed:]
	}
	if fin {
		delete(state.streamBufs, streamID)
	}

	p.mu.Unlock()

	for _, te := range pending {
		p.sink(te)
	}
}

// parseH3Frames parses HTTP/3 frames from a stream buffer.
// Returns bytes consumed.
func (p *H3Parser) parseH3Frames(state *h3ConnState, streamID uint64, data []byte,
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
			p.processH3Headers(state, streamID, payload, pid, processName,
				srcIP, dstIP, srcPort, dstPort, emit)
		case h3FrameData:
			p.processH3Data(state, streamID, payload, pid, processName,
				srcIP, dstIP, srcPort, dstPort, emit)
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
func (p *H3Parser) processH3Headers(state *h3ConnState, streamID uint64, payload []byte,
	pid uint32, processName, srcIP, dstIP string, srcPort, dstPort uint16,
	emit func(*types.TrafficEvent)) {

	decodeFunc := state.qpackDecoder.Decode(payload)
	var fields []qpack.HeaderField
	for {
		hf, err := decodeFunc()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("[h3] QPACK decode error (stream=%d): %v", streamID, err)
			break
		}
		fields = append(fields, hf)
	}
	if len(fields) == 0 {
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
			method: method,
			path:   path,
			host:   authority,
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

		if info := state.activeStreams[streamID]; info != nil {
			info.statusCode = statusCode
			info.contentEncoding = contentEncoding
			info.gotResponse = true
		}

		emit(&types.TrafficEvent{
			Timestamp:       time.Now(),
			SrcIP:           srcIP,
			DstIP:           dstIP,
			SrcPort:         srcPort,
			DstPort:         dstPort,
			Protocol:        "QUIC",
			Direction:       "ingress",
			PID:             pid,
			ProcessName:     processName,
			StatusCode:      statusCode,
			ResponseHeaders: headers,
			TLSIntercepted:  true,
		})
	}
}

// processH3Data handles a DATA frame.
func (p *H3Parser) processH3Data(state *h3ConnState, streamID uint64, payload []byte,
	pid uint32, processName, srcIP, dstIP string, srcPort, dstPort uint16,
	emit func(*types.TrafficEvent)) {

	if len(payload) == 0 {
		return
	}

	snippet := payload
	if len(snippet) > types.BodySnippetMaxLen {
		snippet = snippet[:types.BodySnippetMaxLen]
	}

	info := state.activeStreams[streamID]

	snippetStr := string(snippet)
	if info != nil && strings.EqualFold(info.contentEncoding, "gzip") {
		snippetStr = decompressGzip(snippet)
	}

	te := &types.TrafficEvent{
		Timestamp:      time.Now(),
		SrcIP:          srcIP,
		DstIP:          dstIP,
		SrcPort:        srcPort,
		DstPort:        dstPort,
		Protocol:       "QUIC",
		Direction:      "ingress",
		PID:            pid,
		ProcessName:    processName,
		BodySnippet:    snippetStr,
		TLSIntercepted: true,
	}
	if info != nil {
		te.StatusCode = info.statusCode
		te.URL = info.path
		te.HTTPMethod = info.method
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
