package quic

// QUIC stream reassembly.
//
// HTTP/3 data arrives in STREAM frames that may be fragmented across multiple
// QUIC packets. This module accumulates data per stream ID and delivers
// complete chunks to the HTTP/3 parser.
//
// Limitation: only in-order reassembly is supported (same as existing TC capture).

// streamBuf holds accumulated data for one QUIC stream.
type streamBuf struct {
	data       []byte
	nextOffset uint64 // expected next byte offset for in-order delivery
	fin        bool   // FIN received — stream is complete
}

const maxStreamBufSize = 256 * 1024 // 256 KB

// StreamDataCallback is called when stream data is available for processing.
// streamID: the QUIC stream ID (0, 4, 8, ... for bidi client-initiated)
// data: accumulated stream bytes
// fin: true if this is the final data for the stream
type StreamDataCallback func(streamID uint64, data []byte, fin bool)

// streamAssembler manages per-stream buffers for a connection.
type streamAssembler struct {
	streams  map[uint64]*streamBuf
	callback StreamDataCallback
}

func newStreamAssembler(cb StreamDataCallback) *streamAssembler {
	return &streamAssembler{
		streams:  make(map[uint64]*streamBuf),
		callback: cb,
	}
}

// addFrame processes a STREAM frame, accumulating data and delivering when ready.
func (sa *streamAssembler) addFrame(sf streamFrame) {
	buf, ok := sa.streams[sf.StreamID]
	if !ok {
		buf = &streamBuf{}
		sa.streams[sf.StreamID] = buf
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
		if len(buf.data) > 0 && sa.callback != nil {
			sa.callback(sf.StreamID, buf.data, false)
			buf.data = nil
		}
		buf.nextOffset = sf.Offset
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
		sa.callback(sf.StreamID, buf.data, buf.fin)
		buf.data = nil
		if buf.fin {
			delete(sa.streams, sf.StreamID)
		}
	}
}

// cleanup removes idle streams.
func (sa *streamAssembler) cleanup() {
	// Remove empty streams.
	for id, buf := range sa.streams {
		if len(buf.data) == 0 && buf.fin {
			delete(sa.streams, id)
		}
	}
	// Cap total streams.
	if len(sa.streams) > 256 {
		for id := range sa.streams {
			delete(sa.streams, id)
			if len(sa.streams) <= 128 {
				break
			}
		}
	}
}
