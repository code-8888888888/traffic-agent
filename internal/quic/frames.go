package quic

// QUIC frame parsing (RFC 9000 §12.4).
//
// We only parse frames we care about:
//   - STREAM (0x08-0x0F): carries HTTP/3 data
//   - CONNECTION_CLOSE (0x1C-0x1D): connection termination
//   - PADDING (0x00), PING (0x01), ACK (0x02-0x03): skip
//   - All other frames: skip by consuming their length

// frameType constants.
const (
	framePadding         = 0x00
	framePing            = 0x01
	frameAck             = 0x02
	frameAckECN          = 0x03
	frameResetStream     = 0x04
	frameStopSending     = 0x05
	frameCrypto          = 0x06
	frameNewToken        = 0x07
	frameStreamBase      = 0x08 // 0x08-0x0F: STREAM with various flags
	frameMaxData         = 0x10
	frameMaxStreamData   = 0x11
	frameMaxStreams       = 0x12
	frameMaxStreamsBidi  = 0x12
	frameMaxStreamsUni   = 0x13
	frameDataBlocked     = 0x14
	frameStreamDataBlocked = 0x15
	frameStreamsBlocked   = 0x16
	frameNewConnectionID = 0x18
	frameRetireConnectionID = 0x19
	framePathChallenge   = 0x1A
	framePathResponse    = 0x1B
	frameConnectionClose = 0x1C
	frameConnectionCloseApp = 0x1D
	frameHandshakeDone   = 0x1E
)

// streamFrame represents a parsed STREAM frame.
type streamFrame struct {
	StreamID uint64
	Offset   uint64
	Length   int
	Fin      bool
	Data     []byte
}

// parseFrames parses QUIC frames from decrypted payload and returns any STREAM frames found.
// Other frame types are skipped.
func parseFrames(payload []byte) ([]streamFrame, [][]byte, error) {
	var streams []streamFrame
	var newCIDs [][]byte
	off := 0

	for off < len(payload) {
		frameType, n, err := decodeVarint(payload[off:])
		if err != nil {
			return streams, newCIDs, nil // best effort
		}
		off += n

		switch {
		case frameType == framePadding:
			// PADDING is a single zero byte (already consumed as the varint).
			continue

		case frameType == framePing:
			// PING is just the type byte.
			continue

		case frameType == frameAck || frameType == frameAckECN:
			if err := skipACKFrame(payload[off:], &off, frameType == frameAckECN); err != nil {
				return streams, newCIDs, nil
			}

		case frameType >= frameStreamBase && frameType <= frameStreamBase+0x07:
			sf, consumed, err := parseStreamFrame(payload[off:], frameType)
			if err != nil {
				return streams, newCIDs, nil
			}
			streams = append(streams, sf)
			off += consumed

		case frameType == frameResetStream:
			off += skipResetStream(payload[off:])

		case frameType == frameStopSending:
			off += skipStopSending(payload[off:])

		case frameType == frameCrypto:
			off += skipCryptoFrame(payload[off:])

		case frameType == frameNewToken:
			off += skipNewToken(payload[off:])

		case frameType == frameMaxData || frameType == frameDataBlocked:
			// Single varint.
			_, vn, _ := decodeVarint(payload[off:])
			off += vn

		case frameType == frameMaxStreamData || frameType == frameStreamDataBlocked:
			// Stream ID + value.
			_, vn, _ := decodeVarint(payload[off:])
			off += vn
			_, vn, _ = decodeVarint(payload[off:])
			off += vn

		case frameType == frameMaxStreamsBidi || frameType == frameMaxStreamsUni ||
			frameType == frameStreamsBlocked || frameType == frameStreamsBlocked+1:
			_, vn, _ := decodeVarint(payload[off:])
			off += vn

		case frameType == frameNewConnectionID:
			cid, consumed := parseNewConnectionIDFrame(payload[off:])
			off += consumed
			if len(cid) > 0 {
				newCIDs = append(newCIDs, cid)
			}

		case frameType == frameRetireConnectionID:
			_, vn, _ := decodeVarint(payload[off:])
			off += vn

		case frameType == framePathChallenge || frameType == framePathResponse:
			off += 8 // fixed 8 bytes

		case frameType == frameConnectionClose || frameType == frameConnectionCloseApp:
			// Connection closing — stop parsing.
			return streams, newCIDs, nil

		case frameType == frameHandshakeDone:
			// No payload.
			continue

		default:
			// Unknown frame type with no length — can't skip. Stop parsing.
			return streams, newCIDs, nil
		}
	}

	return streams, newCIDs, nil
}

// parseStreamFrame parses a STREAM frame body (after the type byte).
// STREAM frame flags (in the lower 3 bits of type):
//   0x01: OFF bit — offset field present
//   0x02: LEN bit — length field present
//   0x04: FIN bit — final data for stream
func parseStreamFrame(data []byte, frameType uint64) (streamFrame, int, error) {
	off := 0
	flags := byte(frameType & 0x07)

	// Stream ID (always present).
	streamID, n, err := decodeVarint(data[off:])
	if err != nil {
		return streamFrame{}, 0, err
	}
	off += n

	// Offset (if OFF bit set).
	var offset uint64
	if flags&0x01 != 0 {
		offset, n, err = decodeVarint(data[off:])
		if err != nil {
			return streamFrame{}, 0, err
		}
		off += n
	}

	// Length (if LEN bit set).
	var length int
	if flags&0x02 != 0 {
		l, n, err := decodeVarint(data[off:])
		if err != nil {
			return streamFrame{}, 0, err
		}
		off += n
		length = int(l)
	} else {
		// No length field — data extends to end of packet.
		length = len(data) - off
	}

	if off+length > len(data) {
		length = len(data) - off
	}

	fin := flags&0x04 != 0

	sf := streamFrame{
		StreamID: streamID,
		Offset:   offset,
		Length:   length,
		Fin:      fin,
		Data:     data[off : off+length],
	}
	return sf, off + length, nil
}

// Skip helpers for frame types we don't process.

func skipACKFrame(data []byte, off *int, ecn bool) error {
	// Largest Acknowledged.
	_, n, err := decodeVarint(data)
	if err != nil {
		return err
	}
	pos := n
	// ACK Delay.
	_, n, _ = decodeVarint(data[pos:])
	pos += n
	// ACK Range Count.
	rangeCount, n, _ := decodeVarint(data[pos:])
	pos += n
	// First ACK Range.
	_, n, _ = decodeVarint(data[pos:])
	pos += n
	// Additional ACK Ranges (gap + range pairs).
	for i := uint64(0); i < rangeCount; i++ {
		_, n, _ = decodeVarint(data[pos:])
		pos += n
		_, n, _ = decodeVarint(data[pos:])
		pos += n
	}
	// ECN counts (3 varints).
	if ecn {
		for i := 0; i < 3; i++ {
			_, n, _ = decodeVarint(data[pos:])
			pos += n
		}
	}
	*off += pos
	return nil
}

func skipResetStream(data []byte) int {
	pos := 0
	_, n, _ := decodeVarint(data[pos:]); pos += n // Stream ID
	_, n, _ = decodeVarint(data[pos:]); pos += n // App Error Code
	_, n, _ = decodeVarint(data[pos:]); pos += n // Final Size
	return pos
}

func skipStopSending(data []byte) int {
	pos := 0
	_, n, _ := decodeVarint(data[pos:]); pos += n // Stream ID
	_, n, _ = decodeVarint(data[pos:]); pos += n // App Error Code
	return pos
}

func skipCryptoFrame(data []byte) int {
	pos := 0
	_, n, _ := decodeVarint(data[pos:]); pos += n // Offset
	length, n, _ := decodeVarint(data[pos:]); pos += n // Length
	pos += int(length) // Data
	return pos
}

func skipNewToken(data []byte) int {
	pos := 0
	length, n, _ := decodeVarint(data[pos:]); pos += n
	pos += int(length)
	return pos
}

func parseNewConnectionIDFrame(data []byte) ([]byte, int) {
	pos := 0
	_, n, _ := decodeVarint(data[pos:]); pos += n // Sequence Number
	_, n, _ = decodeVarint(data[pos:]); pos += n // Retire Prior To
	if pos < len(data) {
		connIDLen := int(data[pos]); pos++
		if pos+connIDLen+16 <= len(data) {
			cid := make([]byte, connIDLen)
			copy(cid, data[pos:pos+connIDLen])
			pos += connIDLen
			pos += 16 // Stateless Reset Token
			return cid, pos
		}
		pos += connIDLen
		pos += 16
	}
	return nil, pos
}
