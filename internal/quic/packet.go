package quic

// QUIC packet header parsing (RFC 9000 §17).
//
// QUIC packets come in two forms:
//   - Long Header: used during handshake (Initial, 0-RTT, Handshake, Retry)
//   - Short Header (1-RTT): used for post-handshake application data
//
// We only process 1-RTT (short header) packets since those carry application data
// (HTTP/3) encrypted with the keys we extract from NSS.

import (
	"encoding/binary"
	"fmt"
)

// QUIC packet types (long header).
const (
	packetTypeInitial   = 0x0
	packetTypeZeroRTT   = 0x1
	packetTypeHandshake = 0x2
	packetTypeRetry     = 0x3
)

// quicHeader holds parsed QUIC packet header fields.
type quicHeader struct {
	IsLong     bool
	Version    uint32
	DCID       []byte // Destination Connection ID
	SCID       []byte // Source Connection ID (long header only)
	PacketType byte   // long header only
	// For short header, HeaderLen is set after header protection removal.
	HeaderLen    int
	PayloadStart int // offset into packet where the encrypted payload begins
	RawBytes     []byte
}

// parseShortHeader parses a QUIC short header (1-RTT) packet.
// dcidLen must be known from the connection state (typically 8-20 bytes).
// Returns header info with HeaderLen set to the minimum (before PN decoding).
func parseShortHeader(data []byte, dcidLen int) (*quicHeader, error) {
	if len(data) < 1+dcidLen+1 { // first byte + DCID + at least 1 byte PN
		return nil, fmt.Errorf("short header: packet too small (%d bytes)", len(data))
	}

	firstByte := data[0]
	// Short header: fixed bit (0x40) must be 1, header form (0x80) must be 0.
	if firstByte&0x80 != 0 {
		return nil, fmt.Errorf("not a short header packet (form bit set)")
	}
	if firstByte&0x40 == 0 {
		return nil, fmt.Errorf("short header: fixed bit not set")
	}

	dcid := make([]byte, dcidLen)
	copy(dcid, data[1:1+dcidLen])

	return &quicHeader{
		IsLong:       false,
		DCID:         dcid,
		HeaderLen:    1 + dcidLen, // minimum; actual depends on PN length
		PayloadStart: 0,          // set after header protection removal
		RawBytes:     data,
	}, nil
}

// parseLongHeader parses a QUIC long header packet.
func parseLongHeader(data []byte) (*quicHeader, error) {
	if len(data) < 7 {
		return nil, fmt.Errorf("long header: packet too small (%d bytes)", len(data))
	}

	firstByte := data[0]
	if firstByte&0x80 == 0 {
		return nil, fmt.Errorf("not a long header packet")
	}

	version := binary.BigEndian.Uint32(data[1:5])
	dcidLen := int(data[5])
	if len(data) < 6+dcidLen+1 {
		return nil, fmt.Errorf("long header: DCID truncated")
	}
	dcid := make([]byte, dcidLen)
	copy(dcid, data[6:6+dcidLen])

	off := 6 + dcidLen
	scidLen := int(data[off])
	off++
	if len(data) < off+scidLen {
		return nil, fmt.Errorf("long header: SCID truncated")
	}
	scid := make([]byte, scidLen)
	copy(scid, data[off:off+scidLen])
	off += scidLen

	packetType := (firstByte & 0x30) >> 4

	return &quicHeader{
		IsLong:     true,
		Version:    version,
		DCID:       dcid,
		SCID:       scid,
		PacketType: packetType,
		HeaderLen:  off,
		RawBytes:   data,
	}, nil
}

// isShortHeader returns true if the first byte indicates a short header.
func isShortHeader(firstByte byte) bool {
	return firstByte&0x80 == 0 && firstByte&0x40 != 0
}

// isLongHeader returns true if the first byte indicates a long header.
func isLongHeader(firstByte byte) bool {
	return firstByte&0x80 != 0
}

// splitCoalescedPackets splits coalesced QUIC packets from a single UDP datagram.
// QUIC allows multiple packets in one UDP datagram; only long header packets can
// be coalesced (their lengths are self-describing). Short header packets are always last.
func splitCoalescedPackets(data []byte) [][]byte {
	var packets [][]byte
	for len(data) > 0 {
		if len(data) < 1 {
			break
		}
		if isShortHeader(data[0]) {
			// Short header is always the last packet in a coalesced datagram.
			packets = append(packets, data)
			break
		}
		if !isLongHeader(data[0]) {
			// Unknown format — treat as single packet.
			packets = append(packets, data)
			break
		}
		// Long header: parse to find length.
		pktLen, err := longHeaderPacketLength(data)
		if err != nil || pktLen <= 0 || pktLen > len(data) {
			packets = append(packets, data)
			break
		}
		packets = append(packets, data[:pktLen])
		data = data[pktLen:]
	}
	return packets
}

// longHeaderPacketLength returns the total length of a long header QUIC packet.
func longHeaderPacketLength(data []byte) (int, error) {
	if len(data) < 7 {
		return 0, fmt.Errorf("too short")
	}

	dcidLen := int(data[5])
	off := 6 + dcidLen
	if off >= len(data) {
		return 0, fmt.Errorf("DCID truncated")
	}
	scidLen := int(data[off])
	off += 1 + scidLen

	packetType := (data[0] & 0x30) >> 4
	if packetType == packetTypeInitial {
		// Initial packets have a token length varint before the length.
		tokenLen, n, err := decodeVarint(data[off:])
		if err != nil {
			return 0, err
		}
		off += n + int(tokenLen)
	}

	if off >= len(data) {
		return 0, fmt.Errorf("truncated before length")
	}

	// Read Length varint.
	payloadLen, n, err := decodeVarint(data[off:])
	if err != nil {
		return 0, err
	}
	off += n

	return off + int(payloadLen), nil
}

// decodeVarint decodes a QUIC variable-length integer (RFC 9000 §16).
// Returns (value, bytes consumed, error).
func decodeVarint(data []byte) (uint64, int, error) {
	if len(data) < 1 {
		return 0, 0, fmt.Errorf("empty varint")
	}
	prefix := data[0] >> 6
	length := 1 << prefix
	if len(data) < length {
		return 0, 0, fmt.Errorf("varint truncated (need %d, have %d)", length, len(data))
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

// encodeVarintLen returns the number of bytes needed to encode v as a QUIC varint.
func encodeVarintLen(v uint64) int {
	switch {
	case v < 0x40:
		return 1
	case v < 0x4000:
		return 2
	case v < 0x40000000:
		return 4
	default:
		return 8
	}
}
