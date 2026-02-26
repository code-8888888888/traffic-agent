package quic

// QUICProcessor is the main entry point for QUIC packet processing.
// It manages per-connection state, decrypts 1-RTT packets, and delivers
// HTTP/3 stream data to the parser.
//
// Usage:
//   proc := quic.NewProcessor(h3DataSink)
//   proc.RegisterKeys(pid, keys)
//   proc.HandleUDPPacket(ev)
//   proc.FlushExpired(60 * time.Second)

import (
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	tlspkg "github.com/traffic-agent/traffic-agent/internal/tls"
	"github.com/traffic-agent/traffic-agent/internal/types"
)

// Stats counters.
var (
	QUICConnectionsTracked atomic.Int64
	QUICPacketsReceived    atomic.Int64
	QUICPacketsDecrypted   atomic.Int64
	QUICDecryptFailures    atomic.Int64
	QUICH3EventsEmitted    atomic.Int64
	QUICReverseMisses      atomic.Int64
	QUICLongHeaderSkipped  atomic.Int64
)

// QUICStats returns a snapshot of QUIC processing statistics.
func QUICStats() (connections, received, decrypted, failures, h3events int64) {
	return QUICConnectionsTracked.Load(), QUICPacketsReceived.Load(),
		QUICPacketsDecrypted.Load(), QUICDecryptFailures.Load(),
		QUICH3EventsEmitted.Load()
}

// H3DataSink receives reassembled HTTP/3 stream data for parsing.
// isServer indicates whether this data was sent by the server (true) or client (false).
type H3DataSink func(pid uint32, processName string, streamID uint64, isServer bool, data []byte, fin bool,
	srcIP, dstIP string, srcPort, dstPort uint16)

// connState holds per-connection QUIC decryption state.
type connState struct {
	mu         sync.Mutex // serializes stream assembler access
	client     *directionKeys
	server     *directionKeys
	suite      cipherSuite
	dcidLen    int
	pid        uint32
	clientIP   string
	serverIP   string
	clientPort uint16
	serverPort uint16
	streams    *streamAssembler
	updated    time.Time
}

// Processor manages QUIC connections and decrypts packets.
type Processor struct {
	mu          sync.Mutex
	connections map[string]*connState // keyed by DCID (hex)
	pendingKeys []*pendingKeySet     // keys waiting to be matched to a DCID
	h3Sink      H3DataSink
	// Buffer of recent unmatched short header packets. When a new connection
	// is discovered via tryMatchPendingKeys, we replay these to capture
	// the initial server→client data that arrived before the match.
	unmatchedBuf []bufferedPacket
}

type bufferedPacket struct {
	pkt []byte
	ev  *types.RawPacketEvent
}

type pendingKeySet struct {
	pid       uint32
	keys      *tlspkg.ConnectionKeys
	created   time.Time
	matched   bool
}

// NewProcessor creates a QUIC processor.
func NewProcessor(sink H3DataSink) *Processor {
	return &Processor{
		connections: make(map[string]*connState),
		h3Sink:      sink,
	}
}

// RegisterKeys registers a set of QUIC connection keys.
// Called by the QUICKeyStore callback when a complete key set is available.
func (p *Processor) RegisterKeys(pid uint32, keys *tlspkg.ConnectionKeys) {
	p.mu.Lock()
	defer p.mu.Unlock()

	suite := cipherSuiteFromHashType(keys.HashType)

	clientKeys, err := buildDirectionKeys(keys.ClientKey, keys.ClientIV, keys.ClientHP, suite)
	if err != nil {
		log.Printf("[quic] failed to build client keys: %v", err)
		return
	}
	serverKeys, err := buildDirectionKeys(keys.ServerKey, keys.ServerIV, keys.ServerHP, suite)
	if err != nil {
		log.Printf("[quic] failed to build server keys: %v", err)
		return
	}

	pk := &pendingKeySet{
		pid:     pid,
		keys:    keys,
		created: time.Now(),
	}
	// Store pre-built keys in the pending set (via closure in HandleUDPPacket).
	_ = clientKeys
	_ = serverKeys

	p.pendingKeys = append(p.pendingKeys, pk)

	// Evict old pending keys.
	if len(p.pendingKeys) > 32 {
		p.pendingKeys = p.pendingKeys[len(p.pendingKeys)-16:]
	}

	log.Printf("[quic] registered keys for PID %d (suite=%d, pending=%d)",
		pid, suite, len(p.pendingKeys))
}

// HandleUDPPacket processes a UDP packet that may contain QUIC data.
func (p *Processor) HandleUDPPacket(ev *types.RawPacketEvent) {
	if len(ev.Payload) < 2 {
		return
	}
	QUICPacketsReceived.Add(1)

	// Split coalesced packets.
	packets := splitCoalescedPackets(ev.Payload)

	for _, pkt := range packets {
		if len(pkt) < 1 {
			continue
		}

		// We only process short header (1-RTT) packets.
		if !isShortHeader(pkt[0]) {
			QUICLongHeaderSkipped.Add(1)
			continue
		}

		p.processShortHeaderPacket(pkt, ev)
	}
}

func (p *Processor) processShortHeaderPacket(pkt []byte, ev *types.RawPacketEvent) {
	p.mu.Lock()

	// Try all known DCID lengths (typically 8, but can be 0-20).
	// Firefox uses 3-byte CIDs, so we must include small sizes.
	var conn *connState
	var dcidLen int
	for _, dl := range commonDCIDLengths {
		if 1+dl > len(pkt) {
			continue
		}
		dcidHex := hex.EncodeToString(pkt[1 : 1+dl])
		if c, ok := p.connections[dcidHex]; ok {
			conn = c
			dcidLen = dl
			break
		}
	}

	if conn == nil {
		// Try existing connections — handles reverse-direction DCID.
		// In QUIC each endpoint uses a different DCID, so ingress packets
		// carry a different DCID than egress packets for the same connection.
		nConns := len(p.connections)
		isServer := isQUICServerPort(ev.SrcPort)
		if matched, matchedLen := p.tryMatchExistingConnection(pkt, ev); matched != nil {
			conn = matched
			dcidLen = matchedLen
			dcidHex := hex.EncodeToString(pkt[1 : 1+dcidLen])
			p.connections[dcidHex] = conn
			log.Printf("[quic] registered reverse DCID %s (pid=%d, isServer=%v)", dcidHex, conn.pid, isServer)
		} else if nConns > 0 {
			QUICReverseMisses.Add(1)
			if QUICReverseMisses.Load()%50 == 1 {
				log.Printf("[quic] reverse miss: src=%s:%d dst=%s:%d isServer=%v conns=%d pkt[0]=%02x len=%d",
					ev.SrcIP, ev.SrcPort, ev.DstIP, ev.DstPort, isServer, nConns, pkt[0], len(pkt))
			}
		}
	}

	if conn == nil {
		// Try to match with pending keys by attempting decryption.
		conn = p.tryMatchPendingKeys(pkt, ev)
		if conn == nil {
			// Buffer this packet for later replay if a connection is discovered.
			p.bufferUnmatched(pkt, ev)
			p.mu.Unlock()
			return
		}
		dcidLen = conn.dcidLen
		// New connection discovered — replay buffered packets.
		p.replayBuffered()
	}

	conn.updated = time.Now()
	p.mu.Unlock()

	// Determine direction: if the server port is the src, we're reading server→client.
	isServer := isQUICServerPort(ev.SrcPort)

	var keys *directionKeys
	if isServer {
		keys = conn.server
	} else {
		keys = conn.client
	}
	if keys == nil {
		QUICDecryptFailures.Add(1)
		return
	}

	plaintext, _, err := decryptShortHeaderPacket(pkt, dcidLen, keys, conn.suite)
	if err != nil {
		QUICDecryptFailures.Add(1)
		return
	}
	QUICPacketsDecrypted.Add(1)

	// Parse QUIC frames.
	frames, newCIDs, err := parseFrames(plaintext)
	if err != nil {
		return
	}

	// Register any NEW_CONNECTION_ID frames for faster future lookups.
	if len(newCIDs) > 0 {
		p.mu.Lock()
		for _, cid := range newCIDs {
			cidHex := hex.EncodeToString(cid)
			if _, exists := p.connections[cidHex]; !exists {
				p.connections[cidHex] = conn
			}
		}
		p.mu.Unlock()
	}

	// Process STREAM frames through the assembler.
	conn.mu.Lock()
	for _, sf := range frames {
		conn.streams.addFrame(sf, isServer)
	}
	conn.mu.Unlock()
}

// tryMatchExistingConnection tries to decrypt a packet with each existing
// connection's keys. This handles reverse-direction DCIDs — in QUIC, client
// and server use different DCIDs, so the first direction to be matched
// registers one DCID, and this function discovers the other.
// Must be called with p.mu held.
func (p *Processor) tryMatchExistingConnection(pkt []byte, ev *types.RawPacketEvent) (*connState, int) {
	// Deduplicate — multiple DCIDs may map to the same connection.
	seen := make(map[*connState]bool)
	for _, conn := range p.connections {
		if seen[conn] {
			continue
		}
		seen[conn] = true

		// Try both directions — the isQUICServerPort heuristic may be
		// wrong, and QUIC connections can use any port.
		for _, keys := range []*directionKeys{conn.server, conn.client} {
			if keys == nil {
				continue
			}
			for _, dcidLen := range allDCIDLengths(conn.dcidLen) {
				if 1+dcidLen+4+16 > len(pkt) {
					continue
				}
				_, _, err := decryptShortHeaderPacket(pkt, dcidLen, keys, conn.suite)
				if err == nil {
					return conn, dcidLen
				}
			}
		}
	}
	return nil, 0
}

// tryMatchPendingKeys attempts to decrypt a packet with each pending key set
// to find the right one. On success, creates a new connState.
func (p *Processor) tryMatchPendingKeys(pkt []byte, ev *types.RawPacketEvent) *connState {
	isServer := isQUICServerPort(ev.SrcPort)

	for _, pk := range p.pendingKeys {
		if pk.matched {
			continue
		}
		// Expired.
		if time.Since(pk.created) > 30*time.Second {
			continue
		}

		suite := cipherSuiteFromHashType(pk.keys.HashType)

		// Try common DCID lengths.
		for _, dcidLen := range commonDCIDLengths {
			if 1+dcidLen+4+16 > len(pkt) {
				continue
			}

			// Try BOTH directions' keys — the isQUICServerPort heuristic
			// may be wrong, and we want to match whichever direction arrives first.
			type dirAttempt struct {
				key, iv, hp []byte
				isServerDir bool
			}
			attempts := []dirAttempt{
				{pk.keys.ClientKey, pk.keys.ClientIV, pk.keys.ClientHP, false},
				{pk.keys.ServerKey, pk.keys.ServerIV, pk.keys.ServerHP, true},
			}
			// Try the expected direction first.
			if isServer {
				attempts[0], attempts[1] = attempts[1], attempts[0]
			}

			for _, att := range attempts {
				keys, err := buildDirectionKeys(att.key, att.iv, att.hp, suite)
				if err != nil {
					continue
				}

				_, _, err = decryptShortHeaderPacket(pkt, dcidLen, keys, suite)
				if err != nil {
					continue
				}

				// Success! Create connection state.
				pk.matched = true

				clientKeys, _ := buildDirectionKeys(pk.keys.ClientKey, pk.keys.ClientIV, pk.keys.ClientHP, suite)
				serverKeys, _ := buildDirectionKeys(pk.keys.ServerKey, pk.keys.ServerIV, pk.keys.ServerHP, suite)

				pid := pk.pid

				// Determine canonical client/server endpoints using the actual
				// decryption result, not just the port heuristic.
				var clientIP, serverIP string
				var clientPort, serverPort uint16
				if att.isServerDir {
					// Matched with server keys → packet is server→client.
					clientIP = ev.DstIP.String()
					serverIP = ev.SrcIP.String()
					clientPort = ev.DstPort
					serverPort = ev.SrcPort
				} else {
					// Matched with client keys → packet is client→server.
					clientIP = ev.SrcIP.String()
					serverIP = ev.DstIP.String()
					clientPort = ev.SrcPort
					serverPort = ev.DstPort
				}

				conn := &connState{
					client:     clientKeys,
					server:     serverKeys,
					suite:      suite,
					dcidLen:    dcidLen,
					pid:        pid,
					clientIP:   clientIP,
					serverIP:   serverIP,
					clientPort: clientPort,
					serverPort: serverPort,
					updated:    time.Now(),
				}
				conn.streams = newStreamAssembler(func(streamID uint64, isServerDir bool, data []byte, fin bool) {
					if p.h3Sink != nil {
						QUICH3EventsEmitted.Add(1)
						// Always pass canonical (client→server) direction;
						// H3 parser uses isServer to separate per-direction buffers.
						p.h3Sink(pid, "", streamID, isServerDir, data, fin, clientIP, serverIP, clientPort, serverPort)
					}
				})

				dcidHex := hex.EncodeToString(pkt[1 : 1+dcidLen])
				p.connections[dcidHex] = conn
				QUICConnectionsTracked.Add(1)

				log.Printf("[quic] matched keys to DCID %s (pid=%d, dcidLen=%d, suite=%d, dir=%v)",
					dcidHex, pid, dcidLen, suite, att.isServerDir)
				return conn
			}
		}
	}
	return nil
}

func buildDirectionKeys(key, iv, hp []byte, suite cipherSuite) (*directionKeys, error) {
	if len(key) == 0 || len(iv) == 0 || len(hp) == 0 {
		return nil, fmt.Errorf("incomplete keys")
	}
	aead, err := newAEAD(suite, key)
	if err != nil {
		return nil, err
	}
	return &directionKeys{
		key:  key,
		iv:   iv,
		hp:   hp,
		aead: aead,
	}, nil
}

// FlushExpired removes connections idle longer than maxAge.
func (p *Processor) FlushExpired(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	p.mu.Lock()
	defer p.mu.Unlock()

	// Count unique expired connections (multiple DCIDs may map to the same connState).
	expired := make(map[*connState]bool)
	for dcid, conn := range p.connections {
		if conn.updated.Before(cutoff) {
			delete(p.connections, dcid)
			expired[conn] = true
		}
	}
	QUICConnectionsTracked.Add(-int64(len(expired)))

	// Evict expired pending keys.
	n := 0
	for _, pk := range p.pendingKeys {
		if time.Since(pk.created) < 30*time.Second && !pk.matched {
			p.pendingKeys[n] = pk
			n++
		}
	}
	p.pendingKeys = p.pendingKeys[:n]
}

// Stop performs cleanup.
func (p *Processor) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.connections = make(map[string]*connState)
	p.pendingKeys = nil
}

const maxUnmatchedBuf = 512

// bufferUnmatched stores an unmatched short header packet for later replay.
// Must be called with p.mu held.
func (p *Processor) bufferUnmatched(pkt []byte, ev *types.RawPacketEvent) {
	// Copy packet data since it may be reused by the caller.
	pktCopy := make([]byte, len(pkt))
	copy(pktCopy, pkt)
	p.unmatchedBuf = append(p.unmatchedBuf, bufferedPacket{pkt: pktCopy, ev: ev})
	if len(p.unmatchedBuf) > maxUnmatchedBuf {
		p.unmatchedBuf = p.unmatchedBuf[len(p.unmatchedBuf)-maxUnmatchedBuf/2:]
	}
}

// replayBuffered tries to match and process buffered packets against all
// known connections. Called after a new connection is discovered.
// Must be called with p.mu held.
func (p *Processor) replayBuffered() {
	if len(p.unmatchedBuf) == 0 {
		return
	}

	replayed := 0
	var remaining []bufferedPacket
	for _, bp := range p.unmatchedBuf {
		// Try direct DCID lookup.
		var conn *connState
		var dcidLen int
		for _, dl := range commonDCIDLengths {
			if 1+dl > len(bp.pkt) {
				continue
			}
			dcidHex := hex.EncodeToString(bp.pkt[1 : 1+dl])
			if c, ok := p.connections[dcidHex]; ok {
				conn = c
				dcidLen = dl
				break
			}
		}
		// Try reverse match.
		if conn == nil {
			if matched, matchedLen := p.tryMatchExistingConnection(bp.pkt, bp.ev); matched != nil {
				conn = matched
				dcidLen = matchedLen
				dcidHex := hex.EncodeToString(bp.pkt[1 : 1+dcidLen])
				p.connections[dcidHex] = conn
			}
		}
		if conn == nil {
			remaining = append(remaining, bp)
			continue
		}

		// Matched — process the packet.
		replayed++
		conn.updated = time.Now()
		isServer := isQUICServerPort(bp.ev.SrcPort)
		var keys *directionKeys
		if isServer {
			keys = conn.server
		} else {
			keys = conn.client
		}
		if keys == nil {
			continue
		}
		plaintext, _, err := decryptShortHeaderPacket(bp.pkt, dcidLen, keys, conn.suite)
		if err != nil {
			// Try the other direction.
			if isServer {
				keys = conn.client
			} else {
				keys = conn.server
			}
			if keys == nil {
				continue
			}
			plaintext, _, err = decryptShortHeaderPacket(bp.pkt, dcidLen, keys, conn.suite)
			if err != nil {
				continue
			}
			isServer = !isServer
		}
		QUICPacketsDecrypted.Add(1)

		frames, newCIDs, _ := parseFrames(plaintext)
		for _, cid := range newCIDs {
			cidHex := hex.EncodeToString(cid)
			if _, exists := p.connections[cidHex]; !exists {
				p.connections[cidHex] = conn
			}
		}
		conn.mu.Lock()
		for _, sf := range frames {
			conn.streams.addFrame(sf, isServer)
		}
		conn.mu.Unlock()
	}
	p.unmatchedBuf = remaining

	if replayed > 0 {
		log.Printf("[quic] replayed %d buffered packets (remaining=%d)", replayed, len(remaining))
	}
}

// commonDCIDLengths is the set of DCID lengths to try when looking up or
// matching connections. QUIC allows 0-20 byte CIDs; Firefox uses 3 bytes,
// Google uses 8 bytes. We cover all practical sizes.
var commonDCIDLengths = []int{8, 3, 4, 16, 20, 0, 1, 2, 5, 6, 7, 10, 12}

// allDCIDLengths returns DCID lengths to try, starting with the preferred length.
func allDCIDLengths(preferred int) []int {
	// Start with preferred, then try all 0-20.
	lengths := make([]int, 0, 22)
	lengths = append(lengths, preferred)
	for i := 0; i <= 20; i++ {
		if i != preferred {
			lengths = append(lengths, i)
		}
	}
	return lengths
}

func isQUICServerPort(port uint16) bool {
	return port == 443 || port == 8443
}
