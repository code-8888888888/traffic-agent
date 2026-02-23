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
	h2FrameHeaders      = byte(0x1)
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

	updated time.Time
}

func newH2ConnState() *h2ConnState {
	return &h2ConnState{
		writeDecoder: hpack.NewDecoder(4096, nil),
		readDecoder:  hpack.NewDecoder(4096, nil),
		updated:      time.Now(),
	}
}

// isHTTP2Preface reports whether data begins with the HTTP/2 client connection preface.
func isHTTP2Preface(data []byte) bool {
	return bytes.HasPrefix(data, []byte(h2ClientPreface))
}

// looksLikeHTTP2 heuristically detects HTTP/2 frames when the agent started
// mid-connection and missed the client connection preface.
//
// HTTP/1.1 text always starts with a printable ASCII byte (≥ 0x20): request
// verbs ("GET", "POST", ...) or the response prefix ("HTTP").
// HTTP/2 frame headers begin with a 3-byte length whose high byte is almost
// always 0x00 (frame payloads are ≤ 16 KiB in practice), followed by a
// 1-byte frame type (0x00–0x09).  The combination is unambiguous.
func looksLikeHTTP2(data []byte) bool {
	if len(data) < h2FrameHeaderLen {
		return false
	}
	// Reject if the first byte is a printable ASCII character — that's HTTP/1.1.
	if data[0] >= 0x20 {
		return false
	}
	frameType := data[3]
	return frameType <= h2FrameContinuation
}

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
		if len(state.readBuf)+len(ev.Data) <= maxFlowBufSize {
			state.readBuf = append(state.readBuf, ev.Data...)
		}
		n := state.parseH2Frames(state.readBuf, true, ev.PID, ev.ProcessName,
			func(te *types.TrafficEvent) { pending = append(pending, te) })
		if n > 0 {
			state.readBuf = state.readBuf[n:]
		}
	}
	p.mu.Unlock()

	for _, te := range pending {
		p.sink(te)
	}
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
		}

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
func (s *h2ConnState) emitFromBlock(block []byte, _ uint32, isRead bool, pid uint32, comm string, emit func(*types.TrafficEvent)) {
	dec := s.writeDecoder
	if isRead {
		dec = s.readDecoder
	}

	var fields []hpack.HeaderField
	dec.SetEmitEnabled(true)
	dec.SetEmitFunc(func(f hpack.HeaderField) { fields = append(fields, f) })
	_, err := dec.Write(block)
	dec.SetEmitEnabled(false)

	if err != nil {
		// Dynamic table out of sync (agent missed earlier frames).
		// Reset so future connections can decode correctly.
		if isRead {
			s.readDecoder = hpack.NewDecoder(4096, nil)
		} else {
			s.writeDecoder = hpack.NewDecoder(4096, nil)
		}
		return
	}

	if isRead {
		s.buildResponseEvent(fields, pid, comm, emit)
	} else {
		s.buildRequestEvent(fields, pid, comm, emit)
	}
}

func (s *h2ConnState) buildRequestEvent(fields []hpack.HeaderField, pid uint32, comm string, emit func(*types.TrafficEvent)) {
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
