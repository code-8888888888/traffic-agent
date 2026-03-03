// Package parser — HTTP/2 support for both TLS (SSL uprobe) and cleartext (h2c via TC).
//
// HTTP/2 connections are detected from the client connection preface
// ("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") seen in SSL_write data or TC
// packets.  Once a connection is marked as HTTP/2, all subsequent events
// for the same connection key are decoded using a per-connection HPACK
// decoder rather than the HTTP/1.1 path.
//
// Supported frame types: HEADERS, CONTINUATION, DATA, SETTINGS,
// RST_STREAM, GOAWAY, PUSH_PROMISE, PING, WINDOW_UPDATE.
//
// Limitations:
//   - Connection key is (PID, ConnID) for TLS or 4-tuple for h2c.
//     ConnID is the TCP socket fd (bottom of NSPR layer chain) for Firefox
//     or the SSL* pointer for OpenSSL, unique per connection.
//   - HPACK dynamic table is lost if the agent starts mid-connection.
//     Decode errors reset the decoder so subsequent frames from new
//     connections work.  SETTINGS_HEADER_TABLE_SIZE is tracked so
//     servers negotiating larger tables (e.g. 65536) don't break decoding.
package parser

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/traffic-agent/traffic-agent/internal/types"
)

// defaultHPACKTableSize is the initial HPACK dynamic table size (4096 per spec).
// allowedHPACKTableSize is the maximum the decoder allows via dynamic table
// size updates in the HPACK stream.  Servers commonly negotiate 65536 via
// SETTINGS_HEADER_TABLE_SIZE.  We set a generous upper bound so that
// dynamic table size updates are never rejected.
const allowedHPACKTableSize = 65536

// h2ClientPreface is the fixed 24-byte string that every HTTP/2 client sends
// at the start of a connection before any frames.
const h2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// HTTP/2 frame types we care about.
const (
	h2FrameData         = byte(0x0)
	h2FrameHeaders      = byte(0x1)
	h2FramePriority     = byte(0x2)
	h2FrameRSTStream    = byte(0x3)
	h2FrameSettings     = byte(0x4)
	h2FramePushPromise  = byte(0x5)
	h2FramePing         = byte(0x6)
	h2FrameGoaway       = byte(0x7)
	h2FrameWindowUpdate = byte(0x8)
	h2FrameContinuation = byte(0x9)
)

// HTTP/2 HEADERS frame flags.
const (
	h2FlagEndStream  = byte(0x1)
	h2FlagEndHeaders = byte(0x4)
	h2FlagPadded     = byte(0x8)
	h2FlagPriority   = byte(0x20)
)

// h2FrameHeaderLen is the fixed 9-byte length of every HTTP/2 frame header.
const h2FrameHeaderLen = 9

// h2ConnKey identifies an HTTP/2 connection.  For TLS connections, keyed
// by (PID, ConnID).  ConnID is the SSL-layer PRFileDesc* (for NSPR, resolved
// via fd->lower in BPF) or the SSL* pointer (for OpenSSL), both of which
// are unique per connection.  TID is NOT included because Firefox sends H2
// frames from multiple threads on the same connection — the preface from
// the Socket Thread, subsequent HEADERS from the main thread, etc.
// For h2c (cleartext), keyed by normalized 4-tuple with server-side in Dst.
type h2ConnKey struct {
	PID     uint32
	ConnID  uint64
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
}

// h2EventMeta carries per-event metadata that is threaded through all frame
// processing methods.  It abstracts over TLS vs h2c data sources.
type h2EventMeta struct {
	PID         uint32
	ProcessName string
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	Protocol    string // "TCP" for h2c, "TLS" for SSL path
}

// h2StreamInfo tracks a request's metadata for correlating DATA frames.
type h2StreamInfo struct {
	method          string
	path            string
	host            string
	statusCode      int    // from response HEADERS
	contentEncoding string // for decompression (gzip, br, zstd, deflate)

	// detectedEncoding is set by speculative decompression when
	// contentEncoding is empty (HPACK dynamic table lost content-encoding
	// during mid-connection join).  Once set, subsequent DATA frames on the
	// same stream skip re-probing.
	detectedEncoding string

	// compressedBuf accumulates compressed DATA frame payloads for
	// streaming decompression.  Capped at 64 KB to prevent unbounded growth.
	compressedBuf []byte

	// decompOffset tracks how many decompressed bytes have already been
	// emitted, so subsequent DATA frames show NEW content rather than
	// repeating the beginning.
	decompOffset int
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
	pendingWriteBlock     []byte
	pendingWriteStream    uint32
	pendingWriteEndStream bool // END_STREAM was on the HEADERS frame
	pendingReadBlock      []byte
	pendingReadStream     uint32
	pendingReadEndStream  bool // END_STREAM was on the HEADERS frame

	// Active streams: maps stream ID -> request info for DATA frame correlation.
	activeStreams map[uint32]*h2StreamInfo

	// SETTINGS_MAX_FRAME_SIZE (default 16384, max 16777215).
	maxFrameSize int

	// knownHost tracks the last successfully decoded :authority header for
	// this connection.  When HPACK dynamic table is desynced (mid-connection
	// join), subsequent HEADERS frames may lose :authority.  This provides
	// a connection-level fallback.
	knownHost string

	// Corruption tracking.  NSPR's PR_Write fires for ALL I/O, not just TLS.
	// Non-HTTP/2 data that sneaks through can corrupt frame parsing.  If too
	// many consecutive frames fail validation, the connection state is deleted
	// and a fresh one can be created from the next preface.
	consecutiveErrors int

	// Mid-connection join: when the agent starts after the H2 connection was
	// already established, the HPACK dynamic table is out of sync.  The first
	// few HPACK decode errors are expected and should not count toward the
	// corruption threshold.
	midConnJoin       bool
	hpackRecoveryLeft int // suppress consecutiveErrors for first N HPACK errors

	// confirmedH2 is set to true once at least one valid H2 frame has been
	// successfully consumed on this connection.  Once confirmed, write-side
	// validation is relaxed (no longer requires isValidH2FrameStart) to
	// avoid silently dropping legitimate H2 frames that happen to look
	// ambiguous at the start byte level (e.g., zero-length-prefix DATA).
	confirmedH2 bool

	// Per-connection write event diagnostic counters.
	writeEvents  int
	writeRejects int
	readEvents   int

	updated time.Time
}

// newHPACKDecoder creates an HPACK decoder with a generous allowed max
// dynamic table size so that servers negotiating larger tables (common:
// 65536) don't cause "dynamic table size update too large" errors.
func newHPACKDecoder() *hpack.Decoder {
	d := hpack.NewDecoder(4096, nil)
	d.SetAllowedMaxDynamicTableSize(allowedHPACKTableSize)
	return d
}

func newH2ConnState() *h2ConnState {
	return &h2ConnState{
		writeDecoder: newHPACKDecoder(),
		readDecoder:  newHPACKDecoder(),
		activeStreams: make(map[uint32]*h2StreamInfo),
		maxFrameSize: 16384,
		updated:      time.Now(),
	}
}

// newH2ConnStateMidJoin creates an h2ConnState for mid-connection joins where
// the HPACK dynamic table is out of sync.  The first hpackRecoveryLeft HPACK
// errors are forgiven (don't count toward consecutiveErrors) to prevent the
// state from being prematurely deleted.
func newH2ConnStateMidJoin() *h2ConnState {
	h2MidConnJoins.Add(1)
	return &h2ConnState{
		writeDecoder:      newHPACKDecoder(),
		readDecoder:       newHPACKDecoder(),
		activeStreams:     make(map[uint32]*h2StreamInfo),
		maxFrameSize:      16384,
		midConnJoin:       true,
		hpackRecoveryLeft: 10,
		updated:           time.Now(),
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
//   - All: frame length must be <= 16384 (default SETTINGS_MAX_FRAME_SIZE)
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

	// Sanity: frame length must be reasonable.  Use a generous upper bound
	// since connections may have negotiated a larger SETTINGS_MAX_FRAME_SIZE.
	if frameLen > 1<<20 {
		return false
	}

	switch frameType {
	case h2FrameHeaders: // 0x01
		// HEADERS: stream ID must be > 0, length >= 2 (at least a tiny HPACK block).
		return streamID > 0 && frameLen >= 2
	case h2FrameSettings: // 0x04
		// SETTINGS: stream ID must be 0, length divisible by 6 (each setting is 6 bytes).
		// Also accept ACK (length 0, flag 0x01).
		return streamID == 0 && (frameLen%6 == 0 || frameLen == 0)
	case h2FrameData: // 0x00
		// DATA: stream ID must be > 0, and length >= 1.
		return streamID > 0 && frameLen >= 1
	case h2FramePing: // 0x06
		// PING: fixed 8-byte payload, always on stream 0.
		return frameLen == 8 && streamID == 0
	case h2FrameWindowUpdate: // 0x08
		// WINDOW_UPDATE: fixed 4-byte payload.
		return frameLen == 4
	case h2FrameGoaway: // 0x07
		// GOAWAY: at least 8 bytes (last stream ID + error code), stream ID 0.
		return streamID == 0 && frameLen >= 8
	case h2FrameRSTStream: // 0x03
		// RST_STREAM: fixed 4-byte payload, non-zero stream ID.
		return streamID > 0 && frameLen == 4
	case h2FrameContinuation: // 0x09
		// CONTINUATION: non-zero stream ID, non-empty payload.
		return streamID > 0 && frameLen >= 1
	case h2FramePriority: // 0x02
		// PRIORITY: fixed 5-byte payload, non-zero stream ID.
		return streamID > 0 && frameLen == 5
	}
	return false
}

// maxH2ConsecutiveErrors is the number of consecutive invalid frames before
// the h2ConnState is considered corrupt and is deleted.  This handles the
// case where non-TLS PR_Write data leaks into the HTTP/2 buffer.
const maxH2ConsecutiveErrors = 5

// h2c stats counters.
var (
	h2cConnectionsDetected atomic.Int64
	h2cFramesParsed        atomic.Int64
)

// TLS H2 diagnostic counters.
var (
	h2TLSDataFrames    atomic.Int64
	h2TLSHPACKErrors   atomic.Int64
	h2TLSEventsEmitted atomic.Int64
	h2MidConnJoins     atomic.Int64
	h2StatesExpired    atomic.Int64
	h2LenientDecodes   atomic.Int64
	h2WriteRejections  atomic.Int64
	h2SpecDecomps      atomic.Int64
)

// debugH2 enables verbose H2 frame-level logging.
var debugH2 atomic.Bool

// SetH2Debug enables/disables H2 frame-level debug logging.
func SetH2Debug(on bool) { debugH2.Store(on) }

// H2CStats returns snapshot counters for h2c connections and frames.
func H2CStats() (connections, frames int64) {
	return h2cConnectionsDetected.Load(), h2cFramesParsed.Load()
}

// H2TLSStats returns diagnostic counters for TLS H2 processing.
func H2TLSStats() (dataFrames, hpackErrors, eventsEmitted int64) {
	return h2TLSDataFrames.Load(), h2TLSHPACKErrors.Load(), h2TLSEventsEmitted.Load()
}

// H2StateStats returns diagnostic counters for H2 connection state lifecycle.
func H2StateStats() (midConnJoins, statesExpired, lenientDecodes int64) {
	return h2MidConnJoins.Load(), h2StatesExpired.Load(), h2LenientDecodes.Load()
}

// H2WriteStats returns diagnostic counters for H2 write-side processing.
func H2WriteStats() int64 {
	return h2WriteRejections.Load()
}

// H2SpecDecompStats returns the count of successful speculative decompressions.
func H2SpecDecompStats() int64 {
	return h2SpecDecomps.Load()
}

// handleH2Event appends data to the connection's direction buffer and
// parses as many complete HTTP/2 frames as possible, calling p.sink for
// each decoded request or response event.
func (p *Parser) handleH2Event(state *h2ConnState, data []byte, isRead bool, meta *h2EventMeta, connKey h2ConnKey) {
	var pending []*types.TrafficEvent

	p.mu.Lock()
	state.updated = time.Now()

	if !isRead {
		// Outgoing: browser -> server.
		d := data
		if isHTTP2Preface(d) {
			d = d[len(h2ClientPreface):]
			// New connection on this key — reset all state.
			// Firefox's Socket Thread handles ALL H2 connections, so
			// navigating to a new domain sends a new preface on the
			// same thread.  Stale HPACK tables and activeStreams from
			// the previous domain must be cleared.
			state.writeDecoder = newHPACKDecoder()
			state.readDecoder = newHPACKDecoder()
			state.activeStreams = make(map[uint32]*h2StreamInfo)
			state.writeBuf = nil
			state.readBuf = nil
			state.pendingWriteBlock = nil
			state.pendingReadBlock = nil
			state.pendingWriteStream = 0
			state.pendingReadStream = 0
			state.pendingWriteEndStream = false
			state.pendingReadEndStream = false
			state.consecutiveErrors = 0
			state.maxFrameSize = 16384
			state.knownHost = ""
		}
		if len(d) == 0 {
			p.mu.Unlock()
			return
		}

		// When the write buffer is empty we are NOT in the middle of a
		// partial frame.  Validate that new data looks like HTTP/2 frames
		// to filter out non-TLS PR_Write noise (IPC, files, etc.).
		state.writeEvents++
		if len(state.writeBuf) == 0 && !isValidH2FrameStart(d) {
			if state.confirmedH2 {
				// Confirmed H2 connection — accumulate anyway UNLESS it
				// looks like a TLS record (ciphertext from fd reuse).
				if isTLSRecord(d) {
					h2WriteRejections.Add(1)
					state.writeRejects++
					p.mu.Unlock()
					return
				}
				// Fall through to accumulate — parseH2Frames + consecutiveErrors
				// will detect if this is actually garbage.
			} else {
				h2WriteRejections.Add(1)
				state.writeRejects++
				// Log first 10 rejections per connection for diagnostics.
				if state.writeRejects <= 10 {
					hexBytes := d[:min(16, len(d))]
					log.Printf("[h2-write] REJECTED pid=%d conn=0x%x len=%d first16=%x (reject #%d, total_events=%d)",
						meta.PID, connKey.ConnID, len(d), hexBytes, state.writeRejects, state.writeEvents)
				} else if state.writeRejects%10 == 0 {
					log.Printf("[h2-write] reject summary pid=%d conn=0x%x rejects=%d/%d",
						meta.PID, connKey.ConnID, state.writeRejects, state.writeEvents)
				}
				p.mu.Unlock()
				return
			}
		}

		if len(state.writeBuf)+len(d) <= maxFlowBufSize {
			state.writeBuf = append(state.writeBuf, d...)
		}
		n := state.parseH2Frames(state.writeBuf, false, meta,
			func(te *types.TrafficEvent) { pending = append(pending, te) })
		if n > 0 {
			state.writeBuf = state.writeBuf[n:]
		}
	} else {
		// Incoming: server -> browser.
		state.readEvents++
		if len(state.readBuf) == 0 && !isValidH2FrameStart(data) {
			if debugH2.Load() && len(data) >= 4 {
				log.Printf("[h2-debug] REJECTED read data pid=%d len=%d firstbytes=%x",
					meta.PID, len(data), data[:min(8, len(data))])
			}
			p.mu.Unlock()
			return
		}

		if len(state.readBuf)+len(data) <= maxFlowBufSize {
			state.readBuf = append(state.readBuf, data...)
		}
		n := state.parseH2Frames(state.readBuf, true, meta,
			func(te *types.TrafficEvent) { pending = append(pending, te) })
		if n > 0 {
			state.readBuf = state.readBuf[n:]
		}
	}

	// If too many consecutive errors, the state is corrupt.
	// Delete it so a fresh preface can re-create a clean state.
	if state.consecutiveErrors >= maxH2ConsecutiveErrors {
		log.Printf("[h2] deleting corrupt connection state pid=%d conn=0x%x (consecutive_errors=%d)",
			connKey.PID, connKey.ConnID, state.consecutiveErrors)
		delete(p.h2Conns, connKey)
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
	if frameType > 0x09 { // HTTP/2 defines frame types 0x0 - 0x9
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

// isTLSRecord checks whether data begins with a TLS record header.
// Used to reject ciphertext that leaks in via fd address reuse on confirmed
// H2 connections (where normal isValidH2FrameStart validation is relaxed).
func isTLSRecord(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	// TLS record: content type (0x14-0x17), version (0x0301-0x0304), length
	return data[0] >= 0x14 && data[0] <= 0x17 &&
		data[1] == 0x03 && data[2] >= 0x01 && data[2] <= 0x04
}

// parseH2Frames consumes as many complete HTTP/2 frames as possible from data
// and calls emit for any request or response events decoded from HEADERS frames.
// Returns the number of bytes consumed.
func (s *h2ConnState) parseH2Frames(data []byte, isRead bool, meta *h2EventMeta, emit func(*types.TrafficEvent)) int {
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
			s.processHeadersFrame(payload, flags, streamID, isRead, meta, emit)
		case h2FrameContinuation:
			s.processContinuationFrame(payload, flags, streamID, isRead, meta, emit)
		case h2FrameData:
			s.processDataFrame(payload, flags, streamID, isRead, meta, emit)
		case h2FrameRSTStream:
			s.processRSTStream(streamID)
		case h2FrameSettings:
			s.processSettings(payload, flags, isRead)
		case h2FrameGoaway:
			s.processGoaway(payload)
		case h2FramePushPromise:
			// Server push is deprecated in most browsers; just consume the frame.
		}

		if meta.Protocol == "TCP" {
			h2cFramesParsed.Add(1)
		}

		// Valid frame consumed — reset error counter and mark connection confirmed.
		s.consecutiveErrors = 0
		s.confirmedH2 = true

		consumed += total
		data = data[total:]
	}
	return consumed
}

func (s *h2ConnState) processHeadersFrame(payload []byte, flags byte, streamID uint32, isRead bool, meta *h2EventMeta, emit func(*types.TrafficEvent)) {
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

	endStream := flags&h2FlagEndStream != 0

	if flags&h2FlagEndHeaders != 0 {
		// Complete header block — decode immediately.
		s.emitFromBlock(fragment, streamID, isRead, meta, emit)
		// END_STREAM on response HEADERS: no response body will follow (e.g. 204, 304, HEAD).
		// Only delete on read (response) side — write (request) END_STREAM just means
		// no request body, but we still need the stream info for correlating the response.
		if endStream && isRead {
			delete(s.activeStreams, streamID)
		}
	} else {
		// Partial — accumulate block for following CONTINUATION frames.
		block := make([]byte, len(fragment))
		copy(block, fragment)
		if isRead {
			s.pendingReadBlock = block
			s.pendingReadStream = streamID
			s.pendingReadEndStream = endStream
		} else {
			s.pendingWriteBlock = block
			s.pendingWriteStream = streamID
			s.pendingWriteEndStream = endStream
		}
	}
}

func (s *h2ConnState) processContinuationFrame(payload []byte, flags byte, streamID uint32, isRead bool, meta *h2EventMeta, emit func(*types.TrafficEvent)) {
	if isRead {
		if s.pendingReadBlock == nil {
			if s.midConnJoin {
				// Orphaned CONTINUATION — HEADERS was before agent start.
				block := make([]byte, len(payload))
				copy(block, payload)
				if flags&h2FlagEndHeaders != 0 {
					s.emitFromBlock(block, streamID, isRead, meta, emit)
				} else {
					s.pendingReadBlock = block
					s.pendingReadStream = streamID
					s.pendingReadEndStream = false
				}
			}
			return
		}
		if s.pendingReadStream != streamID {
			return
		}
		s.pendingReadBlock = append(s.pendingReadBlock, payload...)
		if flags&h2FlagEndHeaders != 0 {
			s.emitFromBlock(s.pendingReadBlock, streamID, isRead, meta, emit)
			endStream := s.pendingReadEndStream
			s.pendingReadBlock = nil
			s.pendingReadEndStream = false
			if endStream {
				delete(s.activeStreams, streamID)
			}
		}
	} else {
		if s.pendingWriteBlock == nil {
			if s.midConnJoin {
				// Orphaned CONTINUATION — HEADERS was before agent start.
				block := make([]byte, len(payload))
				copy(block, payload)
				if flags&h2FlagEndHeaders != 0 {
					s.emitFromBlock(block, streamID, isRead, meta, emit)
				} else {
					s.pendingWriteBlock = block
					s.pendingWriteStream = streamID
					s.pendingWriteEndStream = false
				}
			}
			return
		}
		if s.pendingWriteStream != streamID {
			return
		}
		s.pendingWriteBlock = append(s.pendingWriteBlock, payload...)
		if flags&h2FlagEndHeaders != 0 {
			s.emitFromBlock(s.pendingWriteBlock, streamID, isRead, meta, emit)
			s.pendingWriteBlock = nil
			s.pendingWriteEndStream = false
			// Don't delete activeStreams on write-side END_STREAM —
			// we still need stream info for correlating the response.
		}
	}
}

// emitFromBlock HPACK-decodes a complete header block and emits a TrafficEvent.
func (s *h2ConnState) emitFromBlock(block []byte, streamID uint32, isRead bool, meta *h2EventMeta, emit func(*types.TrafficEvent)) {
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

	// Check for silent HPACK desync: decode succeeded but critical
	// pseudo-header is missing.  This happens when the dynamic table
	// has a stale entry that maps to a different field name than expected,
	// or when the request HEADERS was dropped entirely and we only see
	// response HEADERS with desynced dynamic refs.
	if err == nil {
		hasCritical := false
		for _, f := range fields {
			if (!isRead && f.Name == ":method") || (isRead && f.Name == ":status") {
				hasCritical = true
				break
			}
		}
		if !hasCritical && len(block) > 0 {
			lenientFields := lenientDecodeHPACK(block)
			if len(lenientFields) > 0 {
				h2LenientDecodes.Add(1)
				existing := make(map[string]bool, len(fields))
				for _, f := range fields {
					existing[f.Name] = true
				}
				for _, f := range lenientFields {
					if !existing[f.Name] {
						fields = append(fields, f)
						existing[f.Name] = true
					}
				}
			}
		}
	}

	if err != nil {
		h2TLSHPACKErrors.Add(1)
		if h2TLSHPACKErrors.Load()%20 == 1 || debugH2.Load() {
			hexSnippet := fmt.Sprintf("%x", block[:min(32, len(block))])
			log.Printf("[h2] HPACK decode error (isRead=%v stream=%d blockLen=%d partial_fields=%d): %v  block[:32]=%s",
				isRead, streamID, len(block), len(fields), err, hexSnippet)
		}

		// Dynamic table out of sync (agent missed earlier frames or
		// garbage data leaked in).  Replace the stored decoder with a
		// fresh one so future frames on NEW connections decode correctly.
		if isRead {
			s.readDecoder = newHPACKDecoder()
		} else {
			s.writeDecoder = newHPACKDecoder()
		}

		// Strategy 1: use partial fields already captured by emit callback.
		// The emit func fires for each header decoded before the error, so
		// static-table entries like :method, :path are often available.

		// Strategy 2: if no partial fields, retry with a throwaway fresh
		// decoder.  Static table entries decode without dynamic table state.
		if len(fields) == 0 {
			retryDec := newHPACKDecoder()
			retryDec.SetEmitFunc(func(f hpack.HeaderField) { fields = append(fields, f) })
			retryDec.Write(block) // ignore error — we just want static-table entries
		}

		// Strategy 3: lenient HPACK scanner — skips dynamic refs, recovers
		// all static-table and literal header fields.  This recovers :path,
		// :authority, content-type, etc. that appear AFTER the first dynamic
		// ref which causes Strategy 1+2 to stop.
		{
			hasCritical := false
			for _, f := range fields {
				if (!isRead && f.Name == ":path") || (isRead && f.Name == ":status") {
					hasCritical = true
					break
				}
			}
			if !hasCritical {
				lenientFields := lenientDecodeHPACK(block)
				if len(lenientFields) > 0 {
					h2LenientDecodes.Add(1)
					existing := make(map[string]bool, len(fields))
					for _, f := range fields {
						existing[f.Name] = true
					}
					for _, f := range lenientFields {
						if !existing[f.Name] {
							fields = append(fields, f)
							existing[f.Name] = true
						}
					}
				}
			}
		}

		if len(fields) == 0 {
			if s.hpackRecoveryLeft > 0 {
				s.hpackRecoveryLeft--
			} else {
				s.consecutiveErrors++
			}
			return
		}
	}

	if isRead {
		s.buildResponseEvent(fields, streamID, meta, emit)
	} else {
		s.buildRequestEvent(fields, streamID, meta, emit)
	}
}

func (s *h2ConnState) buildRequestEvent(fields []hpack.HeaderField, streamID uint32, meta *h2EventMeta, emit func(*types.TrafficEvent)) {
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
	if debugH2.Load() {
		log.Printf("[h2-debug] request stream=%d method=%q path=%q host=%q nheaders=%d pid=%d",
			streamID, method, path, host, len(fields), meta.PID)
	}
	if method == "" && path == "" {
		return // trailers — skip
	}
	if method == "" {
		method = "UNKNOWN" // HPACK desync lost :method (static index 2/3)
	}
	// Track and fall back to the last known host for this connection.
	// Mid-connection join may lose :authority due to dynamic table desync.
	if host != "" {
		s.knownHost = host
	} else if s.knownHost != "" {
		host = s.knownHost
	}
	if host != "" {
		headers["Host"] = host
	}

	// Track request metadata for DATA frame correlation.
	// Populate activeStreams even if path is empty (mid-connection join with
	// stale HPACK table) so DATA frames get annotated with at least the method.
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
		SrcIP:          meta.SrcIP,
		DstIP:          meta.DstIP,
		SrcPort:        meta.SrcPort,
		DstPort:        meta.DstPort,
		Protocol:       meta.Protocol,
		Direction:      "egress",
		PID:            meta.PID,
		ProcessName:    meta.ProcessName,
		HTTPMethod:     method,
		URL:            path,
		RequestHeaders: headers,
		TLSIntercepted: meta.Protocol == "TLS",
	})
}

func (s *h2ConnState) buildResponseEvent(fields []hpack.HeaderField, streamID uint32, meta *h2EventMeta, emit func(*types.TrafficEvent)) {
	statusCode := 0
	contentEncoding := ""
	headers := make(map[string]string)
	for _, f := range fields {
		if f.Name == ":status" {
			statusCode, _ = strconv.Atoi(f.Value)
		} else if !strings.HasPrefix(f.Name, ":") {
			headers[http.CanonicalHeaderKey(f.Name)] = f.Value
			if strings.EqualFold(f.Name, "content-encoding") {
				contentEncoding = f.Value
			}
		}
	}
	if debugH2.Load() {
		log.Printf("[h2-debug] response stream=%d status=%d nheaders=%d",
			streamID, statusCode, len(fields))
	}
	if statusCode == 0 {
		return // trailers
	}

	// Save response metadata in activeStreams for DATA frame enrichment.
	// Create an entry if one doesn't exist (e.g., mid-connection join where
	// request HEADERS were missed due to stale HPACK table).
	if s.activeStreams == nil {
		s.activeStreams = make(map[uint32]*h2StreamInfo)
	}
	if info := s.activeStreams[streamID]; info != nil {
		info.statusCode = statusCode
		info.contentEncoding = contentEncoding
	} else {
		s.activeStreams[streamID] = &h2StreamInfo{
			statusCode:      statusCode,
			contentEncoding: contentEncoding,
			host:            s.knownHost, // fallback from last known :authority
		}
	}

	emit(&types.TrafficEvent{
		Timestamp:       time.Now(),
		SrcIP:           meta.SrcIP,
		DstIP:           meta.DstIP,
		SrcPort:         meta.SrcPort,
		DstPort:         meta.DstPort,
		Protocol:        meta.Protocol,
		Direction:       "ingress",
		PID:             meta.PID,
		ProcessName:     meta.ProcessName,
		StatusCode:      statusCode,
		ResponseHeaders: headers,
		TLSIntercepted:  meta.Protocol == "TLS",
	})
}

// looksCompressed reports whether data appears to be compressed (binary) rather
// than plaintext.  Returns true if >30% of the first 64 bytes are non-printable
// (outside 0x20-0x7e, excluding \t \n \r).  This avoids triggering speculative
// decompression on plaintext JSON or SSE data.
func looksCompressed(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	n := len(data)
	if n > 64 {
		n = 64
	}
	nonPrintable := 0
	for _, b := range data[:n] {
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
			nonPrintable++
		} else if b > 0x7e {
			nonPrintable++
		}
	}
	return nonPrintable*100/n > 30
}

// tryDecompress attempts to decompress data using each supported codec in order
// of frequency on claude.ai (br, gzip, zstd, deflate).  Returns the codec name
// on the first successful decompression, or "" if all fail.
func tryDecompress(data []byte) string {
	for _, enc := range []string{"br", "gzip", "zstd", "deflate"} {
		result := decompressBodyAt(data, enc, 0)
		// decompressBodyAt returns "<codec-error>" on failure, "" on empty.
		// A successful decode produces non-empty output without the error prefix.
		if result != "" && result[0] != '<' {
			return enc
		}
	}
	return ""
}

// processDataFrame extracts a body snippet from an HTTP/2 DATA frame and
// emits a TrafficEvent correlated with the stream's HEADERS metadata.
// For write (egress) frames, it looks up the request info from activeStreams.
// For read (ingress) frames, it enriches the event with response metadata
// (status code, URL) from the stream's HEADERS if available.
func (s *h2ConnState) processDataFrame(payload []byte, flags byte, streamID uint32, isRead bool, meta *h2EventMeta, emit func(*types.TrafficEvent)) {
	if len(payload) == 0 {
		return
	}

	if meta.Protocol == "TLS" {
		h2TLSDataFrames.Add(1)
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

	// Log substantial DATA frame content for diagnostics.
	if meta.Protocol == "TLS" && len(body) > 20 {
		h2TLSEventsEmitted.Add(1)
		if h2TLSEventsEmitted.Load()%100 == 1 || debugH2.Load() {
			preview := string(body[:min(120, len(body))])
			dir := "write"
			if isRead {
				dir = "read"
			}
			hasInfo := "no-headers"
			if s.activeStreams[streamID] != nil {
				hasInfo = fmt.Sprintf("method=%s url=%s", s.activeStreams[streamID].method, s.activeStreams[streamID].path)
			}
			log.Printf("[h2-data] %s stream=%d len=%d info=%s pid=%d preview=%.120s",
				dir, streamID, len(body), hasInfo, meta.PID, preview)
		}
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

	info := s.activeStreams[streamID]

	if !isRead {
		// Egress DATA: look up the request's HEADERS metadata.
		te := &types.TrafficEvent{
			Timestamp:      time.Now(),
			SrcIP:          meta.SrcIP,
			DstIP:          meta.DstIP,
			SrcPort:        meta.SrcPort,
			DstPort:        meta.DstPort,
			Protocol:       meta.Protocol,
			Direction:      "egress",
			PID:            meta.PID,
			ProcessName:    meta.ProcessName,
			BodySnippet:    string(snippet),
			RequestBody:    string(reqBody),
			TLSIntercepted: meta.Protocol == "TLS",
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
		// Ingress DATA: enrich with response metadata from HEADERS.
		encoding := ""
		if info != nil {
			encoding = info.contentEncoding
			if encoding == "" {
				encoding = info.detectedEncoding // cached from prior speculative hit
			}
		}

		snippetStr := ""
		if encoding != "" && encoding != "identity" && info != nil {
			// Compressed body: accumulate DATA payloads and decompress
			// the full buffer to handle multi-frame compressed streams.
			// Skip already-emitted bytes so each DATA frame shows NEW content.
			const maxCompBuf = 64 * 1024
			if len(info.compressedBuf)+len(body) <= maxCompBuf {
				info.compressedBuf = append(info.compressedBuf, body...)
			}
			snippetStr = decompressBodyAt(info.compressedBuf, encoding, info.decompOffset)
			if snippetStr != "" && !strings.HasPrefix(snippetStr, "<") {
				info.decompOffset += len(snippetStr)
			}
		} else if info != nil && looksCompressed(body) {
			// Speculative decompression: HPACK lost content-encoding
			// (dynamic table ref during mid-connection join).  Try each
			// codec and cache the winner for subsequent DATA frames.
			const maxCompBuf = 64 * 1024
			if len(info.compressedBuf)+len(body) <= maxCompBuf {
				info.compressedBuf = append(info.compressedBuf, body...)
			}
			detected := tryDecompress(info.compressedBuf)
			if detected != "" {
				info.detectedEncoding = detected
				h2SpecDecomps.Add(1)
				snippetStr = decompressBodyAt(info.compressedBuf, detected, info.decompOffset)
				if snippetStr != "" && !strings.HasPrefix(snippetStr, "<") {
					info.decompOffset += len(snippetStr)
				}
			} else {
				snippetStr = string(snippet)
			}
		} else {
			snippetStr = string(snippet)
		}

		te := &types.TrafficEvent{
			Timestamp:      time.Now(),
			SrcIP:          meta.SrcIP,
			DstIP:          meta.DstIP,
			SrcPort:        meta.SrcPort,
			DstPort:        meta.DstPort,
			Protocol:       meta.Protocol,
			Direction:      "ingress",
			PID:            meta.PID,
			ProcessName:    meta.ProcessName,
			BodySnippet:    snippetStr,
			TLSIntercepted: meta.Protocol == "TLS",
		}
		if info != nil {
			te.StatusCode = info.statusCode
			te.URL = info.path
			te.HTTPMethod = info.method
			if info.host != "" {
				te.RequestHeaders = map[string]string{"Host": info.host}
			}
		}
		emit(te)
	}

	// Clean up stream after END_STREAM flag (0x01).
	if flags&h2FlagEndStream != 0 {
		delete(s.activeStreams, streamID)
	}
}

// processRSTStream handles RST_STREAM frames by cleaning up the stream entry.
func (s *h2ConnState) processRSTStream(streamID uint32) {
	delete(s.activeStreams, streamID)
}

// processSettings handles SETTINGS frames.  Tracks SETTINGS_MAX_FRAME_SIZE
// and SETTINGS_HEADER_TABLE_SIZE, and skips ACK frames (flag 0x01).
//
// isRead indicates direction: when the server sends SETTINGS (isRead=true),
// SETTINGS_HEADER_TABLE_SIZE controls the client's encoder table size, which
// corresponds to our writeDecoder.  When the client sends SETTINGS
// (isRead=false), it controls the server's encoder table size, which
// corresponds to our readDecoder.
func (s *h2ConnState) processSettings(payload []byte, flags byte, isRead bool) {
	// ACK frame: flag 0x01, must have empty payload.
	if flags&0x01 != 0 {
		return
	}
	// Parse 6-byte setting pairs: 2-byte ID + 4-byte value.
	for len(payload) >= 6 {
		settingID := binary.BigEndian.Uint16(payload[0:2])
		settingVal := binary.BigEndian.Uint32(payload[2:6])
		payload = payload[6:]

		switch settingID {
		case 0x1: // SETTINGS_HEADER_TABLE_SIZE
			// The sender is telling the receiver what max table size to use
			// when encoding headers.  From our perspective:
			//   server sends (isRead) -> controls client's encoder -> writeDecoder
			//   client sends (!isRead) -> controls server's encoder -> readDecoder
			if isRead {
				s.writeDecoder.SetAllowedMaxDynamicTableSize(settingVal)
			} else {
				s.readDecoder.SetAllowedMaxDynamicTableSize(settingVal)
			}
		case 0x5: // SETTINGS_MAX_FRAME_SIZE
			if settingVal >= 16384 && settingVal <= 16777215 {
				s.maxFrameSize = int(settingVal)
			}
		}
	}
}

// processGoaway handles GOAWAY frames by cleaning up streams beyond lastStreamID.
func (s *h2ConnState) processGoaway(payload []byte) {
	if len(payload) < 8 {
		return
	}
	lastStreamID := binary.BigEndian.Uint32(payload[0:4]) & 0x7FFFFFFF
	for id := range s.activeStreams {
		if id > lastStreamID {
			delete(s.activeStreams, id)
		}
	}
}
