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
	QUICKeyUpdates         atomic.Int64
	QUICKeyUpdateAttempts  atomic.Int64
	QUICKeyUpdateNoSecret  atomic.Int64
	QUICGROSplits          atomic.Int64
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
	// Largest successfully decrypted packet number per direction.
	// Used for PN reconstruction (RFC 9000 §A). -1 means unknown.
	largestClientPN int64
	largestServerPN int64
	// Raw traffic secrets for key update derivation (RFC 9001 §6).
	clientSecret []byte
	serverSecret []byte
	hashType     uint32 // for cipher suite + hash function lookup
	keyGeneration int   // current key generation (0 = initial)
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
	pid     uint32
	keys    *tlspkg.ConnectionKeys
	created time.Time
	matched bool
	// Pre-built direction keys for each cipher suite candidate.
	// SHA-256 secrets could be AES-128-GCM or ChaCha20-Poly1305,
	// so we store both and try each during matching.
	candidates []pendingCandidate
}

type pendingCandidate struct {
	suite      cipherSuite
	clientKeys *directionKeys
	serverKeys *directionKeys
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

	// Build candidate cipher suites. SHA-256 (32-byte) secrets could be
	// AES-128-GCM (16-byte key) or ChaCha20-Poly1305 (32-byte key).
	// We derive separate keys for each cipher suite from the raw secrets.
	var candidates []pendingCandidate
	suites := cipherSuiteCandidates(keys.HashType)
	for _, suite := range suites {
		keyLen := keyLenForSuite(suite)
		hashFunc := hashFuncForType(keys.HashType)

		ck, sk, err := deriveDirectionKeysFromSecrets(keys.ClientSecret, keys.ServerSecret, hashFunc, keyLen, suite)
		if err != nil {
			continue
		}
		candidates = append(candidates, pendingCandidate{
			suite:      suite,
			clientKeys: ck,
			serverKeys: sk,
		})
	}
	if len(candidates) == 0 {
		return
	}

	pk := &pendingKeySet{
		pid:        pid,
		keys:       keys,
		created:    time.Now(),
		candidates: candidates,
	}
	p.pendingKeys = append(p.pendingKeys, pk)
	log.Printf("[quic] registered keys: pid=%d candidates=%d hashType=%d pending=%d",
		pid, len(candidates), keys.HashType, len(p.pendingKeys))

	// Time-based expiry only — no count-based eviction.
	// The SSLKEYLOGFILE produces secrets for ALL TLS 1.3 connections (TCP + QUIC).
	// With a large buffer we keep keys long enough for QUIC handshakes to complete.
	if len(p.pendingKeys) > maxPendingKeys {
		// Evict only expired entries.
		n := 0
		for _, k := range p.pendingKeys {
			if !k.matched && time.Since(k.created) < pendingKeyTTL {
				p.pendingKeys[n] = k
				n++
			}
		}
		p.pendingKeys = p.pendingKeys[:n]
	}
}

const (
	// maxPendingKeys is the hard cap on pending key entries. SSLKEYLOGFILE
	// produces secrets for ALL TLS 1.3 connections — we need a large buffer
	// to keep QUIC keys alive long enough for the handshake to complete.
	maxPendingKeys = 8192
	// pendingKeyTTL is how long pending keys are kept before expiry.
	// 5 minutes is needed because:
	// 1. SSLKEYLOGFILE bulk-loads keys from prior sessions at startup
	// 2. QUIC connections may be established long before matching data packets arrive
	// 3. Firefox reuses QUIC sessions across page navigations
	pendingKeyTTL = 5 * time.Minute
)

// groThreshold is the size above which a short-header packet is likely
// GRO-coalesced (multiple QUIC datagrams merged by the kernel's
// generic-receive-offload). Standard QUIC datagrams are <= MTU (~1500 bytes).
const groThreshold = 1500

// HandleUDPPacket processes a UDP packet that may contain QUIC data.
func (p *Processor) HandleUDPPacket(ev *types.RawPacketEvent) {
	if len(ev.Payload) < 2 {
		return
	}
	QUICPacketsReceived.Add(1)

	// Split coalesced packets (handles long header + trailing short header).
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

		// If the packet is larger than a single QUIC datagram, it's likely a
		// GRO-coalesced buffer (multiple datagrams merged by the kernel).
		// Try splitting into individual QUIC datagrams.
		if len(pkt) > groThreshold {
			p.processGROPacket(pkt, ev)
		} else {
			p.processShortHeaderPacket(pkt, ev)
		}
	}
}

// processGROPacket handles a packet that hit the BPF capture limit (2047 bytes),
// which is likely multiple GRO-coalesced QUIC datagrams. We try decrypting at
// different split points to recover individual datagrams.
func (p *Processor) processGROPacket(pkt []byte, ev *types.RawPacketEvent) {
	// Try to find the connection first.
	p.mu.Lock()
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
	p.mu.Unlock()

	if conn == nil {
		// No connection found — process normally (will try pending keys etc.)
		p.processShortHeaderPacket(pkt, ev)
		return
	}

	// Try to split by decrypting at decreasing datagram sizes.
	// Standard QUIC datagrams are typically 1200-1452 bytes.
	// We try from large to small to maximize data recovered.
	splitSizes := []int{1452, 1400, 1350, 1300, 1252, 1200, 1100, 1000}

	isServer := isQUICServerPort(ev.SrcPort)
	keys := conn.server
	largestPN := conn.largestServerPN
	if !isServer {
		keys = conn.client
		largestPN = conn.largestClientPN
	}
	if keys == nil {
		p.processShortHeaderPacket(pkt, ev)
		return
	}

	off := 0
	decrypted := 0
	for off < len(pkt) {
		remaining := pkt[off:]
		if len(remaining) < 20 { // minimum QUIC packet size
			break
		}

		// If this isn't a short header, stop.
		if !isShortHeader(remaining[0]) {
			break
		}

		// Try full remaining first (in case it's the last datagram).
		pt, pn, err := decryptShortHeaderPacket(remaining, dcidLen, keys, conn.suite, largestPN)
		if err == nil {
			p.deliverDecryptedPacket(conn, pt, pn, isServer, ev)
			decrypted++
			break // remaining was a single complete datagram
		}

		// Try different split sizes.
		found := false
		for _, size := range splitSizes {
			if size > len(remaining) || size < 20 {
				continue
			}
			pt, pn, err := decryptShortHeaderPacket(remaining[:size], dcidLen, keys, conn.suite, largestPN)
			if err == nil {
				p.deliverDecryptedPacket(conn, pt, pn, isServer, ev)
				decrypted++
				if pn > largestPN {
					largestPN = pn
				}
				off += size
				found = true
				break
			}
		}
		if !found {
			break // couldn't find a valid split point
		}
	}

	if decrypted == 0 {
		// GRO splitting didn't work — fall back to normal processing
		// which will try alt direction, key update, etc.
		p.processShortHeaderPacket(pkt, ev)
	} else {
		QUICGROSplits.Add(int64(decrypted))
	}
}

// deliverDecryptedPacket processes a successfully decrypted QUIC packet.
func (p *Processor) deliverDecryptedPacket(conn *connState, plaintext []byte, pn int64, isServer bool, ev *types.RawPacketEvent) {
	QUICPacketsDecrypted.Add(1)

	// Update the largest PN for this direction.
	if isServer {
		if pn > conn.largestServerPN {
			conn.largestServerPN = pn
		}
	} else {
		if pn > conn.largestClientPN {
			conn.largestClientPN = pn
		}
	}

	// Parse QUIC frames.
	frames, newCIDs, err := parseFrames(plaintext)
	if err != nil {
		return
	}

	// Register any NEW_CONNECTION_ID frames.
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

	// Process STREAM frames.
	conn.mu.Lock()
	for _, sf := range frames {
		conn.streams.addFrame(sf, isServer)
	}
	conn.mu.Unlock()
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
			log.Printf("[quic] registered reverse DCID %s (pid=%d, isServer=%v, largestPN_c=%d largestPN_s=%d)",
				dcidHex, conn.pid, isServer, conn.largestClientPN, conn.largestServerPN)
		} else if nConns > 0 {
			QUICReverseMisses.Add(1)
			if QUICReverseMisses.Load()%50 == 1 {
				// Log DCID candidates for debugging.
				var dcidSample string
				if len(pkt) >= 9 {
					dcidSample = hex.EncodeToString(pkt[1:9])
				} else if len(pkt) > 1 {
					dcidSample = hex.EncodeToString(pkt[1:])
				}
				log.Printf("[quic] reverse miss: src=%s:%d dst=%s:%d isServer=%v conns=%d pkt[0]=%02x len=%d dcid8=%s",
					ev.SrcIP, ev.SrcPort, ev.DstIP, ev.DstPort, isServer, nConns, pkt[0], len(pkt), dcidSample)
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

	// Attempt decryption, with fallback for DCID length collisions.
	plaintext, pn, isServer := p.tryDecrypt(conn, pkt, dcidLen, ev)
	if plaintext == nil {
		// DCID length collision: the DCID lookup found a match at a short length
		// (e.g., 3 bytes) but the actual DCID might be longer (e.g., 8 bytes for
		// a different connection). Fall back to try-decrypt against all connections.
		p.mu.Lock()
		if matched, matchedLen := p.tryMatchExistingConnection(pkt, ev); matched != nil && matched != conn {
			dcidHex := hex.EncodeToString(pkt[1 : 1+matchedLen])
			p.connections[dcidHex] = matched
			p.mu.Unlock()
			matched.updated = time.Now()
			plaintext, pn, isServer = p.tryDecrypt(matched, pkt, matchedLen, ev)
			if plaintext != nil {
				conn = matched
				dcidLen = matchedLen
			}
		} else {
			p.mu.Unlock()
		}
	}

	if plaintext == nil {
		QUICDecryptFailures.Add(1)
		if QUICDecryptFailures.Load()%10 == 1 {
			dcidHex := hex.EncodeToString(pkt[1 : 1+dcidLen])
			log.Printf("[quic] decrypt fail: dcid=%s dcidLen=%d pid=%d gen=%d suite=%d pktLen=%d pkt0=%02x largestPN_c=%d largestPN_s=%d conn=%s:%d→%s:%d pkt_src=%s:%d→%s:%d",
				dcidHex, dcidLen, conn.pid, conn.keyGeneration, conn.suite,
				len(pkt), pkt[0], conn.largestClientPN, conn.largestServerPN,
				conn.clientIP, conn.clientPort, conn.serverIP, conn.serverPort,
				ev.SrcIP, ev.SrcPort, ev.DstIP, ev.DstPort)
		}
		return
	}
	QUICPacketsDecrypted.Add(1)

	// Update the largest PN for this direction.
	if isServer {
		if pn > conn.largestServerPN {
			conn.largestServerPN = pn
		}
	} else {
		if pn > conn.largestClientPN {
			conn.largestClientPN = pn
		}
	}

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

// tryDecrypt attempts to decrypt a packet on a known connection.
// Tries: primary direction → alternate direction → key update (up to 8 gens).
// Returns (plaintext, pn, isServer) or (nil, 0, false) on failure.
func (p *Processor) tryDecrypt(conn *connState, pkt []byte, dcidLen int, ev *types.RawPacketEvent) ([]byte, int64, bool) {
	isServer := isQUICServerPort(ev.SrcPort)

	var keys *directionKeys
	if isServer {
		keys = conn.server
	} else {
		keys = conn.client
	}
	if keys == nil {
		return nil, 0, false
	}

	// Get the largest PN for this direction (for PN reconstruction).
	largestPN := conn.largestClientPN
	if isServer {
		largestPN = conn.largestServerPN
	}

	plaintext, pn, err := decryptShortHeaderPacket(pkt, dcidLen, keys, conn.suite, largestPN)
	if err != nil {
		// Try the other direction's keys (port heuristic may be wrong).
		var altKeys *directionKeys
		altLargest := conn.largestServerPN
		if isServer {
			altKeys = conn.client
			altLargest = conn.largestClientPN
		} else {
			altKeys = conn.server
		}
		if altKeys != nil {
			if pt, p2, e := decryptShortHeaderPacket(pkt, dcidLen, altKeys, conn.suite, altLargest); e == nil {
				plaintext = pt
				pn = p2
				isServer = !isServer
				err = nil
			}
		}
	}
	if err != nil {
		// Try QUIC Key Update (RFC 9001 §6): derive next-generation keys.
		if pt, p2 := p.tryKeyUpdate(conn, pkt, dcidLen, isServer); pt != nil {
			return pt, p2, isServer
		}
		// Log the first error for diagnostics.
		if QUICDecryptFailures.Load()%10 == 0 {
			log.Printf("[quic] tryDecrypt failed: %v (pktLen=%d dcidLen=%d)", err, len(pkt), dcidLen)
		}
		return nil, 0, false
	}
	return plaintext, pn, isServer
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
		// Use actual largestPN for PN reconstruction — critical for connections
		// where PN has advanced past 255 (1-byte truncated PN won't reconstruct
		// correctly with largestPN=-1).
		type dirAttempt struct {
			keys      *directionKeys
			largestPN int64
		}
		attempts := []dirAttempt{
			{conn.server, conn.largestServerPN},
			{conn.client, conn.largestClientPN},
		}
		for _, att := range attempts {
			if att.keys == nil {
				continue
			}
			for _, dcidLen := range allDCIDLengths(conn.dcidLen) {
				if 1+dcidLen+4+16 > len(pkt) {
					continue
				}
				// Try with actual largestPN first (correct for advanced PN spaces).
				_, _, err := decryptShortHeaderPacket(pkt, dcidLen, att.keys, conn.suite, att.largestPN)
				if err == nil {
					return conn, dcidLen
				}
				// Fallback: try with largestPN=-1 for early packets where PN < 256.
				if att.largestPN > 0 {
					_, _, err = decryptShortHeaderPacket(pkt, dcidLen, att.keys, conn.suite, -1)
					if err == nil {
						return conn, dcidLen
					}
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
		if time.Since(pk.created) > pendingKeyTTL {
			continue
		}

		// Try each cipher suite candidate and DCID length.
		for _, cand := range pk.candidates {
			for _, dcidLen := range commonDCIDLengths {
				if 1+dcidLen+4+16 > len(pkt) {
					continue
				}

				// Try both directions — the port heuristic may be wrong.
				type dirAttempt struct {
					keys        *directionKeys
					isServerDir bool
				}
				attempts := []dirAttempt{
					{cand.clientKeys, false},
					{cand.serverKeys, true},
				}
				if isServer {
					attempts[0], attempts[1] = attempts[1], attempts[0]
				}

				for _, att := range attempts {
					_, _, err := decryptShortHeaderPacket(pkt, dcidLen, att.keys, cand.suite, -1)
					if err != nil {
						continue
					}

					// Success! Create connection state.
					pk.matched = true
					pid := pk.pid

					var clientIP, serverIP string
					var clientPort, serverPort uint16
					if att.isServerDir {
						clientIP = ev.DstIP.String()
						serverIP = ev.SrcIP.String()
						clientPort = ev.DstPort
						serverPort = ev.SrcPort
					} else {
						clientIP = ev.SrcIP.String()
						serverIP = ev.DstIP.String()
						clientPort = ev.SrcPort
						serverPort = ev.DstPort
					}

					conn := &connState{
						client:          cand.clientKeys,
						server:          cand.serverKeys,
						suite:           cand.suite,
						dcidLen:         dcidLen,
						pid:             pid,
						clientIP:        clientIP,
						serverIP:        serverIP,
						clientPort:      clientPort,
						serverPort:      serverPort,
						updated:         time.Now(),
						largestClientPN: -1,
						largestServerPN: -1,
						clientSecret:    pk.keys.ClientSecret,
						serverSecret:    pk.keys.ServerSecret,
						hashType:        pk.keys.HashType,
					}
					conn.streams = newStreamAssembler(func(streamID uint64, isServerDir bool, data []byte, fin bool) {
						if p.h3Sink != nil {
							QUICH3EventsEmitted.Add(1)
							p.h3Sink(pid, "", streamID, isServerDir, data, fin, clientIP, serverIP, clientPort, serverPort)
						}
					})

					dcidHex := hex.EncodeToString(pkt[1 : 1+dcidLen])
					p.connections[dcidHex] = conn
					QUICConnectionsTracked.Add(1)

					log.Printf("[quic] matched keys to DCID %s (pid=%d, dcidLen=%d, suite=%d, dir=%v)",
						dcidHex, pid, dcidLen, cand.suite, att.isServerDir)
					return conn
				}
			}
		}
	}
	return nil
}

// maxKeyUpdateGens is the maximum number of key update generations to try.
// QUIC endpoints can rotate keys multiple times; if we miss the transition
// packets we need to fast-forward through several generations.
const maxKeyUpdateGens = 8

// tryKeyUpdate attempts QUIC Key Update (RFC 9001 §6) when normal decryption
// fails on a matched connection. Derives up to maxKeyUpdateGens generations
// of keys (advancing both directions together per RFC 9001 §6) and retries
// decryption at each generation. On success, updates the connection state
// with the new keys. Returns (plaintext, pn) or (nil, 0) on failure.
func (p *Processor) tryKeyUpdate(conn *connState, pkt []byte, dcidLen int, isServer bool) ([]byte, int64) {
	QUICKeyUpdateAttempts.Add(1)
	if conn.clientSecret == nil || conn.serverSecret == nil {
		QUICKeyUpdateNoSecret.Add(1)
		return nil, 0
	}

	// Advance both directions together through generations.
	// RFC 9001 §6: both endpoints update read and write keys together.
	clientSecret := conn.clientSecret
	serverSecret := conn.serverSecret

	for gen := 1; gen <= maxKeyUpdateGens; gen++ {
		// Derive next generation for both directions.
		newClientSecret, newClientKeys, err := deriveKeyUpdate(clientSecret, conn.hashType, conn.suite)
		if err != nil {
			break
		}
		// HP keys are NOT updated during key update (RFC 9001 §6.3) — reuse originals.
		newClientKeys.hp = conn.client.hp

		newServerSecret, newServerKeys, err := deriveKeyUpdate(serverSecret, conn.hashType, conn.suite)
		if err != nil {
			break
		}
		newServerKeys.hp = conn.server.hp

		// Try decryption with both directions at this generation.
		// Prefer the direction matching the port heuristic, then try the other.
		type dirAttempt struct {
			keys      *directionKeys
			largestPN int64
			serverDir bool
		}
		attempts := []dirAttempt{
			{newServerKeys, conn.largestServerPN, true},
			{newClientKeys, conn.largestClientPN, false},
		}
		if !isServer {
			attempts[0], attempts[1] = attempts[1], attempts[0]
		}

		for _, att := range attempts {
			plaintext, pn, err := decryptShortHeaderPacket(pkt, dcidLen, att.keys, conn.suite, att.largestPN)
			if err != nil {
				continue
			}

			// Success — update both directions to this generation.
			conn.keyGeneration += gen
			conn.client = newClientKeys
			conn.clientSecret = newClientSecret
			conn.server = newServerKeys
			conn.serverSecret = newServerSecret
			QUICKeyUpdates.Add(1)
			log.Printf("[quic] key update success: gen=%d direction=%v advanced=%d dcidLen=%d pid=%d",
				conn.keyGeneration, att.serverDir, gen, dcidLen, conn.pid)
			return plaintext, pn
		}

		// Chain to next generation.
		clientSecret = newClientSecret
		serverSecret = newServerSecret
	}

	return nil, 0
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
		if time.Since(pk.created) < pendingKeyTTL && !pk.matched {
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
		largestPN := conn.largestClientPN
		if isServer {
			largestPN = conn.largestServerPN
		}
		plaintext, pn, err := decryptShortHeaderPacket(bp.pkt, dcidLen, keys, conn.suite, largestPN)
		if err != nil {
			// Try the other direction.
			if isServer {
				keys = conn.client
				largestPN = conn.largestClientPN
			} else {
				keys = conn.server
				largestPN = conn.largestServerPN
			}
			if keys == nil {
				continue
			}
			plaintext, pn, err = decryptShortHeaderPacket(bp.pkt, dcidLen, keys, conn.suite, largestPN)
			if err != nil {
				continue
			}
			isServer = !isServer
		}
		QUICPacketsDecrypted.Add(1)

		// Update largest PN for this direction.
		if isServer {
			if pn > conn.largestServerPN {
				conn.largestServerPN = pn
			}
		} else {
			if pn > conn.largestClientPN {
				conn.largestClientPN = pn
			}
		}

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
