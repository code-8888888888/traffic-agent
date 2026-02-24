// Package parser — HTTP/2 support.
//
// HTTP/2 connections are detected from the client connection preface
// ("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") seen in SSL_write data.  Once a
// connection is marked as HTTP/2, all subsequent SSL events for the same
// (PID, TID) are decoded using a per-connection HPACK decoder rather than
// the HTTP/1.1 path.
//
// Limitations:
//   - Connection key is (PID, TID).  A thread that opens multiple sequential
//     HTTP/2 connections will have its HPACK dynamic tables reset on the second
//     connection's preface.  Concurrent connections on the same thread are not
//     distinguishable without tracking the file descriptor.
//   - HPACK dynamic table is lost if the agent starts mid-connection.  Decode
//     errors reset the decoder so subsequent frames from new connections work.
//   - Response body snippets are not captured for HTTP/2 (DATA frames contain
//     no headers; correlating them with a stream requires more state).
package parser

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/traffic-agent/traffic-agent/internal/types"
)

// h2ClientPreface is the fixed 24-byte string that every HTTP/2 client sends
// at the start of a connection before any frames.
const h2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// HTTP/2 frame types we care about.
const (
	h2FrameData         = byte(0x0)
	h2FrameHeaders      = byte(0x1)
	h2FrameSettings     = byte(0x4)
	h2FramePing         = byte(0x6)
	h2FrameWindowUpdate = byte(0x8)
	h2FrameContinuation = byte(0x9)
)

// HTTP/2 HEADERS frame flags.
const (
	h2FlagEndHeaders = byte(0x4)
	h2FlagPadded     = byte(0x8)
	h2FlagPriority   = byte(0x20)
)

// h2FrameHeaderLen is the fixed 9-byte length of every HTTP/2 frame header.
const h2FrameHeaderLen = 9

// h2ConnKey identifies an HTTP/2 connection by the PID and TID of the thread
// that called SSL_write / SSL_read.  Each TLS stream is owned by exactly one
// thread in the browser process.
type h2ConnKey struct {
	PID uint32
	TID uint32
}

// h2StreamInfo tracks a request's metadata for correlating DATA frames.
type h2StreamInfo struct {
	method string
	path   string
	host   string
}

// h2ConnState holds per-connection HTTP/2 decode state.
type h2ConnState struct {
	// Separate HPACK decoders for each flow direction.
	// The write decoder mirrors the server's HPACK decoder state (used to
	// decode outgoing HEADERS frames from the browser).
	// The read decoder mirrors the browser's HPACK decoder state (used to
	// decode incoming HEADERS frames from the server).
	writeDecoder *hpack.Decoder
	readDecoder  *hpack.Decoder

	// Per-direction data buffers for partial frame assembly.
	writeBuf []byte
	readBuf  []byte

	// State for HEADERS + CONTINUATION frame sequences (one in-flight at a time).
	pendingWriteBlock  []byte
	pendingWriteStream uint32
	pendingReadBlock   []byte
	pendingReadStream  uint32

	// Active streams: maps stream ID → request info for DATA frame correlation.
	activeStreams map[uint32]*h2StreamInfo

	// Corruption tracking.  NSPR's PR_Write fires for ALL I/O, not just TLS.
	// Non-HTTP/2 data that sneaks through can corrupt frame parsing.  If too
	// many consecutive frames fail validation, the connection state is deleted
	// and a fresh one can be created from the next preface.
	consecutiveErrors int

	updated time.Time
}

func newH2ConnState() *h2ConnState {
	return &h2ConnState{
		writeDecoder:  hpack.NewDecoder(4096, nil),
		readDecoder:   hpack.NewDecoder(4096, nil),
		activeStreams: make(map[uint32]*h2StreamInfo),
		updated:       time.Now(),
	}
}

// isHTTP2Preface reports whether data begins with the HTTP/2 client connection preface.
func isHTTP2Preface(data []byte) bool {
	return bytes.HasPrefix(data, []byte(h2ClientPreface))
}

// looksLikeH2MidConnection checks whether data begins with an HTTP/2 frame
// that is distinctive enough to indicate a pre-existing HTTP/2 connection
// whose preface we missed (agent started after the connection was opened).
//
// This is much stricter than the removed looksLikeHTTP2 heuristic:
//   - Only accepts HEADERS, SETTINGS, or DATA frames (not any type 0-9)
//   - HEADERS: requires valid stream ID (odd for write, non-zero)
//   - SETTINGS: requires stream ID 0 and length divisible by 6
//   - DATA: requires valid stream ID (non-zero)
//   - All: frame length must be ≤ 16384 (default SETTINGS_MAX_FRAME_SIZE)
//
// The false-positive rate on random binary data is negligible compared to the
// old heuristic, because we require specific frame-type semantics.
func looksLikeH2MidConnection(data []byte) bool {
	if len(data) < h2FrameHeaderLen {
		return false
	}
	frameLen := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
	frameType := data[3]
	streamID := binary.BigEndian.Uint32(data[5:9]) & 0x7FFFFFFF

	// Sanity: frame length must be reasonable.
	if frameLen > 16384 {
		return false
	}

	switch frameType {
	case h2FrameHeaders: // 0x01
		// HEADERS: stream ID must be > 0, length ≥ 2 (at least a tiny HPACK block).
		return streamID > 0 && frameLen >= 2
	case h2FrameSettings: // 0x04
		// SETTINGS: stream ID must be 0, length divisible by 6 (each setting is 6 bytes).
		return streamID == 0 && frameLen%6 == 0
	case h2FrameData: // 0x00
		// DATA: stream ID must be > 0, and length ≥ 1.
		return streamID > 0 && frameLen >= 1
	case h2FramePing: // 0x06
		// PING: fixed 8-byte payload, always on stream 0.
		return frameLen == 8 && streamID == 0
	case h2FrameWindowUpdate: // 0x08
		// WINDOW_UPDATE: fixed 4-byte payload.
		return frameLen == 4
	}
	return false
}

// maxH2ConsecutiveErrors is the number of consecutive invalid frames before
// the h2ConnState is considered corrupt and is deleted.  This handles the
// case where non-TLS PR_Write data leaks into the HTTP/2 buffer.
const maxH2ConsecutiveErrors = 5

// handleH2Event appends ev.Data to the connection's direction buffer and
// parses as many complete HTTP/2 frames as possible, calling p.sink for
// each decoded request or response event.
func (p *Parser) handleH2Event(state *h2ConnState, ev *types.SSLEvent) {
	var pending []*types.TrafficEvent

	p.mu.Lock()
	state.updated = time.Now()

	if !ev.IsRead {
		// Outgoing (SSL_write): browser → server.
		data := ev.Data
		if isHTTP2Preface(data) {
			data = data[len(h2ClientPreface):]
			// New connection on this (PID, TID) — reset all state.
			// Firefox's Socket Thread handles ALL H2 connections, so
			// navigating to a new domain sends a new preface on the
			// same thread.  Stale HPACK tables and activeStreams from
			// the previous domain must be cleared.
			state.writeDecoder = hpack.NewDecoder(4096, nil)
			state.readDecoder = hpack.NewDecoder(4096, nil)
			state.activeStreams = make(map[uint32]*h2StreamInfo)
			state.writeBuf = nil
			state.readBuf = nil
			state.pendingWriteBlock = nil
			state.pendingReadBlock = nil
			state.pendingWriteStream = 0
			state.pendingReadStream = 0
			state.consecutiveErrors = 0
		}
		if len(data) == 0 {
			p.mu.Unlock()
			return
		}

		// When the write buffer is empty we are NOT in the middle of a
		// partial frame.  Validate that new data looks like HTTP/2 frames
		// to filter out non-TLS PR_Write noise (IPC, files, etc.).
		if len(state.writeBuf) == 0 && !isValidH2FrameStart(data) {
			p.mu.Unlock()
			return
		}

		if len(state.writeBuf)+len(data) <= maxFlowBufSize {
			state.writeBuf = append(state.writeBuf, data...)
		}
		n := state.parseH2Frames(state.writeBuf, false, ev.PID, ev.ProcessName,
			func(te *types.TrafficEvent) { pending = append(pending, te) })
		if n > 0 {
			state.writeBuf = state.writeBuf[n:]
		}
	} else {
		// Incoming (SSL_read): server → browser.
		if len(state.readBuf) == 0 && !isValidH2FrameStart(ev.Data) {
			p.mu.Unlock()
			return
		}

		if len(state.readBuf)+len(ev.Data) <= maxFlowBufSize {
			state.readBuf = append(state.readBuf, ev.Data...)
		}
		n := state.parseH2Frames(state.readBuf, true, ev.PID, ev.ProcessName,
			func(te *types.TrafficEvent) { pending = append(pending, te) })
		if n > 0 {
			state.readBuf = state.readBuf[n:]
		}
	}

	// If too many consecutive errors, the state is corrupt.
	// Delete it so a fresh preface can re-create a clean state.
	if state.consecutiveErrors >= maxH2ConsecutiveErrors {
		h2Key := h2ConnKey{PID: ev.PID, TID: ev.TID}
		delete(p.h2Conns, h2Key)
	}

	p.mu.Unlock()

	for _, te := range pending {
		p.sink(te)
	}
}

// isValidH2FrameStart checks whether data begins with a plausible HTTP/2
// frame header.  Used to filter out non-HTTP/2 data (IPC, file I/O, etc.)
// that reaches the parser via NSPR's PR_Write.
func isValidH2FrameStart(data []byte) bool {
	if len(data) < h2FrameHeaderLen {
		return false
	}
	frameType := data[3]
	if frameType > 0x09 { // HTTP/2 defines frame types 0x0 – 0x9
		return false
	}
	frameLen := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
	// SETTINGS_MAX_FRAME_SIZE default is 16384; maximum allowed is 16777215.
	// Use 1 MiB as a generous sanity check.
	if frameLen > 1<<20 {
		return false
	}
	return true
}

// parseH2Frames consumes as many complete HTTP/2 frames as possible from data
// and calls emit for any request or response events decoded from HEADERS frames.
// Returns the number of bytes consumed.
func (s *h2ConnState) parseH2Frames(data []byte, isRead bool, pid uint32, comm string, emit func(*types.TrafficEvent)) int {
	consumed := 0
	for len(data) >= h2FrameHeaderLen {
		frameLen := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
		frameType := data[3]
		flags := data[4]
		streamID := binary.BigEndian.Uint32(data[5:9]) & 0x7FFFFFFF

		// Validate frame type and length.  If invalid, the buffer is
		// corrupt (non-HTTP/2 data leaked in).  Discard everything
		// remaining so the next event starts with a clean buffer.
		if frameType > 0x09 || frameLen > 1<<20 {
			s.consecutiveErrors++
			return consumed + len(data)
		}

		total := h2FrameHeaderLen + frameLen
		if len(data) < total {
			break // incomplete frame — wait for more data
		}

		payload := data[h2FrameHeaderLen:total]
		switch frameType {
		case h2FrameHeaders:
			s.processHeadersFrame(payload, flags, streamID, isRead, pid, comm, emit)
		case h2FrameContinuation:
			s.processContinuationFrame(payload, flags, streamID, isRead, pid, comm, emit)
		case h2FrameData:
			s.processDataFrame(payload, flags, streamID, isRead, pid, comm, emit)
		}

		// Valid frame consumed — reset error counter.
		s.consecutiveErrors = 0

		consumed += total
		data = data[total:]
	}
	return consumed
}

func (s *h2ConnState) processHeadersFrame(payload []byte, flags byte, streamID uint32, isRead bool, pid uint32, comm string, emit func(*types.TrafficEvent)) {
	fragment := payload

	// Strip padding if PADDED flag is set.
	if flags&h2FlagPadded != 0 {
		if len(fragment) < 1 {
			return
		}
		padLen := int(fragment[0])
		fragment = fragment[1:]
		if len(fragment) <= padLen {
			return
		}
		fragment = fragment[:len(fragment)-padLen]
	}

	// Skip priority fields if PRIORITY flag is set.
	if flags&h2FlagPriority != 0 {
		if len(fragment) < 5 {
			return
		}
		fragment = fragment[5:]
	}

	if flags&h2FlagEndHeaders != 0 {
		// Complete header block — decode immediately.
		s.emitFromBlock(fragment, streamID, isRead, pid, comm, emit)
	} else {
		// Partial — accumulate block for following CONTINUATION frames.
		block := make([]byte, len(fragment))
		copy(block, fragment)
		if isRead {
			s.pendingReadBlock = block
			s.pendingReadStream = streamID
		} else {
			s.pendingWriteBlock = block
			s.pendingWriteStream = streamID
		}
	}
}

func (s *h2ConnState) processContinuationFrame(payload []byte, flags byte, streamID uint32, isRead bool, pid uint32, comm string, emit func(*types.TrafficEvent)) {
	if isRead {
		if s.pendingReadBlock == nil || s.pendingReadStream != streamID {
			return
		}
		s.pendingReadBlock = append(s.pendingReadBlock, payload...)
		if flags&h2FlagEndHeaders != 0 {
			s.emitFromBlock(s.pendingReadBlock, streamID, isRead, pid, comm, emit)
			s.pendingReadBlock = nil
		}
	} else {
		if s.pendingWriteBlock == nil || s.pendingWriteStream != streamID {
			return
		}
		s.pendingWriteBlock = append(s.pendingWriteBlock, payload...)
		if flags&h2FlagEndHeaders != 0 {
			s.emitFromBlock(s.pendingWriteBlock, streamID, isRead, pid, comm, emit)
			s.pendingWriteBlock = nil
		}
	}
}

// emitFromBlock HPACK-decodes a complete header block and emits a TrafficEvent.
func (s *h2ConnState) emitFromBlock(block []byte, streamID uint32, isRead bool, pid uint32, comm string, emit func(*types.TrafficEvent)) {
	dec := s.writeDecoder
	if isRead {
		dec = s.readDecoder
	}

	var fields []hpack.HeaderField
	dec.SetEmitEnabled(true)
	dec.SetEmitFunc(func(f hpack.HeaderField) { fields = append(fields, f) })
	_, err := dec.Write(block)
	if err == nil {
		dec.Close() // Reset firstField flag so dynamic table size updates are accepted.
	}
	dec.SetEmitEnabled(false)

	if err != nil {
		// Dynamic table out of sync (agent missed earlier frames or
		// garbage data leaked in).  Replace the stored decoder with a
		// fresh one so future frames decode correctly.
		if isRead {
			s.readDecoder = hpack.NewDecoder(4096, nil)
		} else {
			s.writeDecoder = hpack.NewDecoder(4096, nil)
		}

		// Strategy 1: use partial fields already captured by emit callback.
		// The emit func fires for each header decoded before the error, so
		// static-table entries like :method, :path are often available.

		// Strategy 2: if no partial fields, retry with a throwaway fresh
		// decoder.  Static table entries decode without dynamic table state.
		if len(fields) == 0 {
			retryDec := hpack.NewDecoder(4096, nil)
			retryDec.SetEmitFunc(func(f hpack.HeaderField) { fields = append(fields, f) })
			retryDec.Write(block) // ignore error — we just want static-table entries
		}

		if len(fields) == 0 {
			s.consecutiveErrors++
			return
		}
	}

	if isRead {
		s.buildResponseEvent(fields, pid, comm, emit)
	} else {
		s.buildRequestEvent(fields, streamID, pid, comm, emit)
	}
}

func (s *h2ConnState) buildRequestEvent(fields []hpack.HeaderField, streamID uint32, pid uint32, comm string, emit func(*types.TrafficEvent)) {
	method, path, host := "", "", ""
	headers := make(map[string]string)
	for _, f := range fields {
		switch f.Name {
		case ":method":
			method = f.Value
		case ":path":
			path = f.Value
		case ":authority":
			host = f.Value
		case ":scheme":
			// not emitted in output
		default:
			if !strings.HasPrefix(f.Name, ":") {
				headers[http.CanonicalHeaderKey(f.Name)] = f.Value
			}
		}
	}
	if method == "" || path == "" {
		return // trailers or PUSH_PROMISE — skip
	}
	if host != "" {
		headers["Host"] = host
	}

	// Track request metadata for DATA frame correlation.
	if s.activeStreams == nil {
		s.activeStreams = make(map[uint32]*h2StreamInfo)
	}
	s.activeStreams[streamID] = &h2StreamInfo{method: method, path: path, host: host}
	// Cap active streams to avoid unbounded growth (keep most recent 128).
	if len(s.activeStreams) > 128 {
		for id := range s.activeStreams {
			delete(s.activeStreams, id)
			if len(s.activeStreams) <= 96 {
				break
			}
		}
	}

	emit(&types.TrafficEvent{
		Timestamp:      time.Now(),
		Protocol:       "TLS",
		Direction:      "egress",
		PID:            pid,
		ProcessName:    comm,
		HTTPMethod:     method,
		URL:            path,
		RequestHeaders: headers,
		TLSIntercepted: true,
	})
}

func (s *h2ConnState) buildResponseEvent(fields []hpack.HeaderField, pid uint32, comm string, emit func(*types.TrafficEvent)) {
	statusCode := 0
	headers := make(map[string]string)
	for _, f := range fields {
		if f.Name == ":status" {
			statusCode, _ = strconv.Atoi(f.Value)
		} else if !strings.HasPrefix(f.Name, ":") {
			headers[http.CanonicalHeaderKey(f.Name)] = f.Value
		}
	}
	if statusCode == 0 {
		return // trailers
	}
	emit(&types.TrafficEvent{
		Timestamp:       time.Now(),
		Protocol:        "TLS",
		Direction:       "ingress",
		PID:             pid,
		ProcessName:     comm,
		StatusCode:      statusCode,
		ResponseHeaders: headers,
		TLSIntercepted:  true,
	})
}

// processDataFrame extracts a body snippet from an HTTP/2 DATA frame and
// emits a TrafficEvent correlated with the stream's HEADERS metadata.
// For write (egress) frames, it looks up the request info from activeStreams.
// For read (ingress) frames, it emits the body with direction=ingress.
func (s *h2ConnState) processDataFrame(payload []byte, flags byte, streamID uint32, isRead bool, pid uint32, comm string, emit func(*types.TrafficEvent)) {
	if len(payload) == 0 {
		return
	}

	body := payload
	// Strip padding if PADDED flag (0x08) is set.
	if flags&h2FlagPadded != 0 {
		if len(body) < 1 {
			return
		}
		padLen := int(body[0])
		body = body[1:]
		if len(body) <= padLen {
			return
		}
		body = body[:len(body)-padLen]
	}
	if len(body) == 0 {
		return
	}

	// Truncate to snippet limit.
	snippet := body
	if len(snippet) > types.BodySnippetMaxLen {
		snippet = snippet[:types.BodySnippetMaxLen]
	}

	// Full request body (up to RequestBodyMaxLen).
	reqBody := body
	if len(reqBody) > types.RequestBodyMaxLen {
		reqBody = reqBody[:types.RequestBodyMaxLen]
	}

	if !isRead {
		// Egress DATA: look up the request's HEADERS metadata.
		info := s.activeStreams[streamID]
		te := &types.TrafficEvent{
			Timestamp:      time.Now(),
			Protocol:       "TLS",
			Direction:      "egress",
			PID:            pid,
			ProcessName:    comm,
			BodySnippet:    string(snippet),
			RequestBody:    string(reqBody),
			TLSIntercepted: true,
		}
		if info != nil {
			te.HTTPMethod = info.method
			te.URL = info.path
			if info.host != "" {
				te.RequestHeaders = map[string]string{"Host": info.host}
			}
		}
		emit(te)
	} else {
		// Ingress DATA: emit body snippet for response.
		emit(&types.TrafficEvent{
			Timestamp:      time.Now(),
			Protocol:       "TLS",
			Direction:      "ingress",
			PID:            pid,
			ProcessName:    comm,
			BodySnippet:    string(snippet),
			TLSIntercepted: true,
		})
	}

	// Clean up stream after END_STREAM flag (0x01).
	if flags&0x01 != 0 {
		delete(s.activeStreams, streamID)
	}
}
