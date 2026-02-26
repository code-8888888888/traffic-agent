package quic

// QUIC stream reassembly.
//
// HTTP/3 data arrives in STREAM frames that may be fragmented across multiple
// QUIC packets. This module accumulates data per stream ID and delivers
// complete chunks to the HTTP/3 parser.
//
// Important: QUIC bidirectional streams have independent offset spaces per
// direction. Client→server and server→client data on the same stream ID are
// tracked separately using a (streamID, isServer) composite key.
//
// Limitation: only in-order reassembly is supported (same as existing TC capture).

import "log"

// streamBuf holds accumulated data for one QUIC stream direction.
type streamBuf struct {
	data       []byte
	nextOffset uint64 // expected next byte offset for in-order delivery
	fin        bool   // FIN received — stream is complete
}

const maxStreamBufSize = 256 * 1024 // 256 KB

// streamKey identifies a stream direction uniquely.
type streamKey struct {
	streamID uint64
	isServer bool // true = server→client direction
}

// StreamDataCallback is called when stream data is available for processing.
// streamID: the QUIC stream ID (0, 4, 8, ... for bidi client-initiated)
// isServer: true if data was sent by the server
// data: accumulated stream bytes
// fin: true if this is the final data for the stream
type StreamDataCallback func(streamID uint64, isServer bool, data []byte, fin bool)

// streamAssembler manages per-stream buffers for a connection.
type streamAssembler struct {
	streams  map[streamKey]*streamBuf
	callback StreamDataCallback
}

func newStreamAssembler(cb StreamDataCallback) *streamAssembler {
	return &streamAssembler{
		streams:  make(map[streamKey]*streamBuf),
		callback: cb,
	}
}

// addFrame processes a STREAM frame, accumulating data and delivering when ready.
// isServer indicates whether this frame came from the server direction.
func (sa *streamAssembler) addFrame(sf streamFrame, isServer bool) {
	key := streamKey{streamID: sf.StreamID, isServer: isServer}
	buf, ok := sa.streams[key]
	if !ok {
		buf = &streamBuf{}
		sa.streams[key] = buf
	}

	// In-order delivery: only accept data at the expected offset.
	if sf.Offset != buf.nextOffset {
		// Out-of-order or duplicate — skip for now.
		// Future: could buffer and reorder.
		if sf.Offset < buf.nextOffset {
			// Duplicate or overlap — skip.
			return
		}
		// Gap — deliver what we have and reset.
		log.Printf("[stream-gap] stream=%d isServer=%v expected=%d got=%d gap=%d dataLen=%d fin=%v",
			sf.StreamID, isServer, buf.nextOffset, sf.Offset, sf.Offset-buf.nextOffset, len(sf.Data), sf.Fin)
		if len(buf.data) > 0 && sa.callback != nil {
			sa.callback(sf.StreamID, isServer, buf.data, false)
			buf.data = nil
		}
		buf.nextOffset = sf.Offset
		buf.fin = false // reset FIN on gap
	}

	// Append data.
	if len(buf.data)+len(sf.Data) <= maxStreamBufSize {
		buf.data = append(buf.data, sf.Data...)
	}
	buf.nextOffset += uint64(len(sf.Data))

	if sf.Fin {
		buf.fin = true
	}

	// Deliver accumulated data. For HTTP/3, we deliver incrementally
	// since HTTP/3 frames are self-describing (have length fields).
	if len(buf.data) > 0 && sa.callback != nil {
		sa.callback(sf.StreamID, isServer, buf.data, buf.fin)
		buf.data = nil
		if buf.fin {
			delete(sa.streams, key)
		}
	}
}

// cleanup removes idle streams.
func (sa *streamAssembler) cleanup() {
	// Remove empty streams.
	for key, buf := range sa.streams {
		if len(buf.data) == 0 && buf.fin {
			delete(sa.streams, key)
		}
	}
	// Cap total streams.
	if len(sa.streams) > 256 {
		for key := range sa.streams {
			delete(sa.streams, key)
			if len(sa.streams) <= 128 {
				break
			}
		}
	}
}
