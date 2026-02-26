package tls

// QUICKeyStore accumulates QUIC key derivation events from the BPF probes
// and groups them into complete connection key sets.
//
// tls13_HkdfExpandLabelRaw has no connection ID parameter, so we correlate
// key events by PID + timing window. Each QUIC connection derives 6 keys:
//   "quic key" × 2 directions
//   "quic iv"  × 2 directions
//   "quic hp"  × 2 directions
//
// Keys for the same connection arrive in quick succession (within ~10ms).

import (
	"log"
	"sync"
	"time"

	"github.com/traffic-agent/traffic-agent/internal/types"
)

// ConnectionKeys holds a complete set of QUIC encryption keys for one connection.
type ConnectionKeys struct {
	// Client (local) keys — used for encrypting outgoing packets.
	ClientKey []byte
	ClientIV  []byte
	ClientHP  []byte
	// Server (remote) keys — used for decrypting incoming packets.
	ServerKey []byte
	ServerIV  []byte
	ServerHP  []byte
	// CipherSuite indicator derived from HashType.
	// sha256(4) → AES-128-GCM or ChaCha20; sha384(5) → AES-256-GCM.
	HashType uint32
	PID      uint32
}

// keyGroup accumulates partial key sets for a single connection within a timing window.
type keyGroup struct {
	pid       uint32
	created   time.Time
	keys      []*types.QUICKeyEvent
	delivered bool
}

// KeyCallback is called when a complete set of connection keys is ready.
type KeyCallback func(pid uint32, keys *ConnectionKeys)

// QUICKeyStore accumulates QUIC key events and delivers complete key sets.
type QUICKeyStore struct {
	mu       sync.Mutex
	groups   []*keyGroup
	callback KeyCallback
}

const (
	// keyGroupWindow is the max time window for grouping key events from the same connection.
	keyGroupWindow = 100 * time.Millisecond
	// maxKeyGroups limits the number of pending key groups to prevent unbounded growth.
	maxKeyGroups = 64
)

// NewQUICKeyStore creates a new key store.
func NewQUICKeyStore() *QUICKeyStore {
	return &QUICKeyStore{}
}

// RegisterKeyCallback sets the callback invoked when a complete key set is ready.
func (ks *QUICKeyStore) RegisterKeyCallback(fn KeyCallback) {
	ks.mu.Lock()
	ks.callback = fn
	ks.mu.Unlock()
}

// AddEvent adds a QUIC key event and attempts to form a complete key set.
func (ks *QUICKeyStore) AddEvent(ev *types.QUICKeyEvent) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Find or create a group for this PID within the timing window.
	now := time.Now()
	var group *keyGroup
	for _, g := range ks.groups {
		if g.pid == ev.PID && !g.delivered && now.Sub(g.created) < keyGroupWindow {
			group = g
			break
		}
	}
	if group == nil {
		group = &keyGroup{
			pid:     ev.PID,
			created: now,
		}
		ks.groups = append(ks.groups, group)
		// Evict old groups.
		if len(ks.groups) > maxKeyGroups {
			ks.groups = ks.groups[len(ks.groups)-maxKeyGroups/2:]
		}
	}

	group.keys = append(group.keys, ev)

	// Check if we have a complete set (6 keys: 3 labels × 2 occurrences).
	keys := ks.tryBuildKeys(group)
	if keys == nil {
		return
	}

	group.delivered = true
	cb := ks.callback
	if cb == nil {
		return
	}

	// Deliver outside the lock.
	go cb(ev.PID, keys)
}

// tryBuildKeys attempts to build a ConnectionKeys from the accumulated events.
// Returns nil if the set is incomplete.
//
// The 6 HKDF derivations for a QUIC connection produce keys in order:
//   client: "quic key", "quic iv", "quic hp"
//   server: "quic key", "quic iv", "quic hp"
// We identify client vs server by order of arrival (first 3 = client, next 3 = server).
func (ks *QUICKeyStore) tryBuildKeys(group *keyGroup) *ConnectionKeys {
	if len(group.keys) < 6 {
		return nil
	}

	// Count occurrences of each label.
	labelCount := make(map[string]int)
	for _, ev := range group.keys {
		labelCount[ev.Label]++
	}

	// Need exactly 2 of each label.
	if labelCount["quic key"] < 2 || labelCount["quic iv"] < 2 || labelCount["quic hp"] < 2 {
		return nil
	}

	ck := &ConnectionKeys{
		HashType: group.keys[0].HashType,
		PID:      group.pid,
	}

	// First occurrence of each label → client; second → server.
	seen := make(map[string]int)
	for _, ev := range group.keys {
		seen[ev.Label]++
		isClient := seen[ev.Label] == 1

		data := make([]byte, len(ev.KeyData))
		copy(data, ev.KeyData)

		switch ev.Label {
		case "quic key":
			if isClient {
				ck.ClientKey = data
			} else {
				ck.ServerKey = data
			}
		case "quic iv":
			if isClient {
				ck.ClientIV = data
			} else {
				ck.ServerIV = data
			}
		case "quic hp":
			if isClient {
				ck.ClientHP = data
			} else {
				ck.ServerHP = data
			}
		}
	}

	log.Printf("[quic-keys] complete key set for PID %d: key=%d/%d iv=%d/%d hp=%d/%d hash=%d",
		group.pid,
		len(ck.ClientKey), len(ck.ServerKey),
		len(ck.ClientIV), len(ck.ServerIV),
		len(ck.ClientHP), len(ck.ServerHP),
		ck.HashType)

	return ck
}

// FlushExpired removes key groups older than maxAge.
func (ks *QUICKeyStore) FlushExpired(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	ks.mu.Lock()
	defer ks.mu.Unlock()

	n := 0
	for _, g := range ks.groups {
		if g.created.After(cutoff) {
			ks.groups[n] = g
			n++
		}
	}
	ks.groups = ks.groups[:n]
}
