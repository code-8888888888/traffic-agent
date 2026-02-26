package tls

// KeylogWatcher tails an SSLKEYLOGFILE and derives QUIC encryption keys
// from traffic secrets (CLIENT_TRAFFIC_SECRET_0 / SERVER_TRAFFIC_SECRET_0).
//
// This is the most reliable way to get QUIC keys from Firefox — the BPF uprobe
// approach for tls13_HkdfExpandLabelRaw only captures the IV, since the AEAD key
// and HP key stay as opaque PKCS#11 handles inside NSS and are never extracted
// as raw bytes.
//
// The SSLKEYLOGFILE approach requires Firefox to be started with the env var set:
//   SSLKEYLOGFILE=/path/to/keylog.txt firefox
//
// Key derivation follows RFC 9001 §5.1:
//   quic key = HKDF-Expand-Label(secret, "quic key", "", key_length)
//   quic iv  = HKDF-Expand-Label(secret, "quic iv",  "", 12)
//   quic hp  = HKDF-Expand-Label(secret, "quic hp",  "", key_length)

import (
	"bufio"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

// KeylogWatcher watches an SSLKEYLOGFILE for QUIC traffic secrets and derives
// complete QUIC encryption keys.
type KeylogWatcher struct {
	path     string
	callback KeyCallback
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// NewKeylogWatcher creates a watcher for the given SSLKEYLOGFILE path.
func NewKeylogWatcher(path string) *KeylogWatcher {
	return &KeylogWatcher{
		path:   path,
		stopCh: make(chan struct{}),
	}
}

// RegisterKeyCallback sets the callback invoked when a complete key set is ready.
func (w *KeylogWatcher) RegisterKeyCallback(fn KeyCallback) {
	w.callback = fn
}

// Start begins watching the keylog file for new entries.
func (w *KeylogWatcher) Start() {
	w.wg.Add(1)
	go w.watchLoop()
}

// Stop stops the watcher.
func (w *KeylogWatcher) Stop() {
	close(w.stopCh)
	w.wg.Wait()
}

// secretPair holds a matched client+server traffic secret pair.
type secretPair struct {
	clientRandom []byte // used to correlate client+server secrets
	clientSecret []byte
	serverSecret []byte
}

func (w *KeylogWatcher) watchLoop() {
	defer w.wg.Done()

	// Pending secrets: keyed by hex(client_random)
	pending := make(map[string]*secretPair)

	var offset int64
	for {
		select {
		case <-w.stopCh:
			return
		default:
		}

		entries, newOffset := w.readNewEntries(offset)
		if newOffset > offset {
			offset = newOffset
		}

		for _, entry := range entries {
			key := hex.EncodeToString(entry.clientRandom)
			sp, ok := pending[key]
			if !ok {
				sp = &secretPair{clientRandom: entry.clientRandom}
				pending[key] = sp
			}

			switch entry.label {
			case "CLIENT_TRAFFIC_SECRET_0":
				sp.clientSecret = entry.secret
			case "SERVER_TRAFFIC_SECRET_0":
				sp.serverSecret = entry.secret
			}

			if sp.clientSecret != nil && sp.serverSecret != nil {
				w.deriveAndDeliver(sp)
				delete(pending, key)
			}
		}

		// Clean old pending entries.
		if len(pending) > 256 {
			pending = make(map[string]*secretPair)
		}

		select {
		case <-w.stopCh:
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

type keylogEntry struct {
	label        string
	clientRandom []byte
	secret       []byte
}

func (w *KeylogWatcher) readNewEntries(offset int64) ([]keylogEntry, int64) {
	f, err := os.Open(w.path)
	if err != nil {
		return nil, offset
	}
	defer f.Close()

	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return nil, offset
		}
	}

	var entries []keylogEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 3 {
			continue
		}

		label := parts[0]
		if label != "CLIENT_TRAFFIC_SECRET_0" && label != "SERVER_TRAFFIC_SECRET_0" {
			continue
		}

		clientRandom, err := hex.DecodeString(parts[1])
		if err != nil || len(clientRandom) != 32 {
			continue
		}
		secret, err := hex.DecodeString(parts[2])
		if err != nil || len(secret) == 0 {
			continue
		}

		entries = append(entries, keylogEntry{
			label:        label,
			clientRandom: clientRandom,
			secret:       secret,
		})
	}

	newOffset, _ := f.Seek(0, io.SeekCurrent)
	return entries, newOffset
}

func (w *KeylogWatcher) deriveAndDeliver(sp *secretPair) {
	// Determine cipher suite from secret length:
	//   32 bytes → SHA-256 → AES-128-GCM (16-byte key) or ChaCha20 (32-byte key)
	//   48 bytes → SHA-384 → AES-256-GCM (32-byte key)
	var hashFunc func() hash.Hash
	var keyLen int
	var hashType uint32

	switch len(sp.clientSecret) {
	case 48:
		hashFunc = sha512.New384
		keyLen = 32
		hashType = 5 // sha384
	default:
		hashFunc = sha256.New
		keyLen = 16
		hashType = 4 // sha256
	}

	clientKey, err := hkdfExpandLabel(hashFunc, sp.clientSecret, "quic key", keyLen)
	if err != nil {
		log.Printf("[keylog] derive client key: %v", err)
		return
	}
	clientIV, err := hkdfExpandLabel(hashFunc, sp.clientSecret, "quic iv", 12)
	if err != nil {
		log.Printf("[keylog] derive client iv: %v", err)
		return
	}
	clientHP, err := hkdfExpandLabel(hashFunc, sp.clientSecret, "quic hp", keyLen)
	if err != nil {
		log.Printf("[keylog] derive client hp: %v", err)
		return
	}

	serverKey, err := hkdfExpandLabel(hashFunc, sp.serverSecret, "quic key", keyLen)
	if err != nil {
		log.Printf("[keylog] derive server key: %v", err)
		return
	}
	serverIV, err := hkdfExpandLabel(hashFunc, sp.serverSecret, "quic iv", 12)
	if err != nil {
		log.Printf("[keylog] derive server iv: %v", err)
		return
	}
	serverHP, err := hkdfExpandLabel(hashFunc, sp.serverSecret, "quic hp", keyLen)
	if err != nil {
		log.Printf("[keylog] derive server hp: %v", err)
		return
	}

	keys := &ConnectionKeys{
		ClientKey: clientKey,
		ClientIV:  clientIV,
		ClientHP:  clientHP,
		ServerKey: serverKey,
		ServerIV:  serverIV,
		ServerHP:  serverHP,
		HashType:  hashType,
	}

	log.Printf("[keylog] derived QUIC keys: key=%d/%d iv=%d/%d hp=%d/%d hash=%d",
		len(keys.ClientKey), len(keys.ServerKey),
		len(keys.ClientIV), len(keys.ServerIV),
		len(keys.ClientHP), len(keys.ServerHP),
		keys.HashType)

	if w.callback != nil {
		w.callback(0, keys)
	}
}

// hkdfExpandLabel implements TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1):
//
//	HKDF-Expand-Label(Secret, Label, Context, Length) =
//	    HKDF-Expand(Secret, HkdfLabel, Length)
//
//	where HkdfLabel = struct {
//	    uint16 length;
//	    opaque label<7..255> = "tls13 " + Label;
//	    opaque context<0..255>;
//	};
func hkdfExpandLabel(hashFunc func() hash.Hash, secret []byte, label string, length int) ([]byte, error) {
	// Build the HKDF info (HkdfLabel struct).
	fullLabel := "tls13 " + label
	info := make([]byte, 2+1+len(fullLabel)+1)
	info[0] = byte(length >> 8)
	info[1] = byte(length)
	info[2] = byte(len(fullLabel))
	copy(info[3:], fullLabel)
	info[3+len(fullLabel)] = 0 // empty context

	out := make([]byte, length)
	r := hkdf.Expand(hashFunc, secret, info)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("HKDF-Expand-Label(%s): %w", label, err)
	}
	return out, nil
}
