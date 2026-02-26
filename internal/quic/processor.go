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
)

// QUICStats returns a snapshot of QUIC processing statistics.
func QUICStats() (connections, received, decrypted, failures, h3events int64) {
	return QUICConnectionsTracked.Load(), QUICPacketsReceived.Load(),
		QUICPacketsDecrypted.Load(), QUICDecryptFailures.Load(),
		QUICH3EventsEmitted.Load()
}

// H3DataSink receives reassembled HTTP/3 stream data for parsing.
type H3DataSink func(pid uint32, processName string, streamID uint64, data []byte, fin bool,
	srcIP, dstIP string, srcPort, dstPort uint16)

// connState holds per-connection QUIC decryption state.
type connState struct {
	client  *directionKeys
	server  *directionKeys
	suite   cipherSuite
	dcidLen int
	pid     uint32
	streams *streamAssembler
	updated time.Time
}

// Processor manages QUIC connections and decrypts packets.
type Processor struct {
	mu          sync.Mutex
	connections map[string]*connState // keyed by DCID (hex)
	pendingKeys []*pendingKeySet     // keys waiting to be matched to a DCID
	h3Sink      H3DataSink
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
			// Long header packets are handshake-related.
			// We could extract DCIDs from Initial packets for early mapping,
			// but for MVP we wait for 1-RTT data.
			continue
		}

		p.processShortHeaderPacket(pkt, ev)
	}
}

func (p *Processor) processShortHeaderPacket(pkt []byte, ev *types.RawPacketEvent) {
	p.mu.Lock()

	// Try all known DCID lengths (typically 8, but can be 0-20).
	// Most implementations use a fixed length per connection.
	var conn *connState
	var dcidHex string
	for _, dcidLen := range []int{8, 16, 20, 4, 0} {
		if 1+dcidLen > len(pkt) {
			continue
		}
		dcidHex = hex.EncodeToString(pkt[1 : 1+dcidLen])
		if c, ok := p.connections[dcidHex]; ok {
			conn = c
			break
		}
	}

	if conn == nil {
		// Try to match with pending keys by attempting decryption.
		conn = p.tryMatchPendingKeys(pkt, ev)
		if conn == nil {
			p.mu.Unlock()
			return
		}
		dcidHex = hex.EncodeToString(pkt[1 : 1+conn.dcidLen])
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

	plaintext, _, err := decryptShortHeaderPacket(pkt, conn.dcidLen, keys, conn.suite)
	if err != nil {
		QUICDecryptFailures.Add(1)
		return
	}
	QUICPacketsDecrypted.Add(1)

	// Parse QUIC frames.
	frames, err := parseFrames(plaintext)
	if err != nil {
		return
	}

	// Process STREAM frames through the assembler.
	for _, sf := range frames {
		conn.streams.addFrame(sf)
	}
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
		for _, dcidLen := range []int{8, 16, 20, 4} {
			if 1+dcidLen+4+16 > len(pkt) {
				continue
			}

			// Build keys for the direction we're receiving from.
			var tryKey, tryIV, tryHP []byte
			if isServer {
				tryKey, tryIV, tryHP = pk.keys.ServerKey, pk.keys.ServerIV, pk.keys.ServerHP
			} else {
				tryKey, tryIV, tryHP = pk.keys.ClientKey, pk.keys.ClientIV, pk.keys.ClientHP
			}

			keys, err := buildDirectionKeys(tryKey, tryIV, tryHP, suite)
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

			srcIP := ev.SrcIP.String()
			dstIP := ev.DstIP.String()
			srcPort := ev.SrcPort
			dstPort := ev.DstPort
			pid := pk.pid

			conn := &connState{
				client:  clientKeys,
				server:  serverKeys,
				suite:   suite,
				dcidLen: dcidLen,
				pid:     pid,
				updated: time.Now(),
			}
			conn.streams = newStreamAssembler(func(streamID uint64, data []byte, fin bool) {
				if p.h3Sink != nil {
					QUICH3EventsEmitted.Add(1)
					p.h3Sink(pid, "", streamID, data, fin, srcIP, dstIP, srcPort, dstPort)
				}
			})

			dcidHex := hex.EncodeToString(pkt[1 : 1+dcidLen])
			p.connections[dcidHex] = conn
			QUICConnectionsTracked.Add(1)

			log.Printf("[quic] matched keys to DCID %s (pid=%d, dcidLen=%d, suite=%d)",
				dcidHex, pid, dcidLen, suite)
			return conn
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

	for dcid, conn := range p.connections {
		if conn.updated.Before(cutoff) {
			delete(p.connections, dcid)
			QUICConnectionsTracked.Add(-1)
		}
	}

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

func isQUICServerPort(port uint16) bool {
	return port == 443 || port == 8443
}
