package quic

// QUIC packet protection: header protection removal and AEAD decryption.
//
// RFC 9001 §5: QUIC uses AEAD (AES-128-GCM, AES-256-GCM, or ChaCha20-Poly1305)
// for payload encryption and AES-ECB or ChaCha20 for header protection.
//
// The process to decrypt a 1-RTT (short header) packet:
//   1. Sample 16 bytes from the encrypted payload (at a fixed offset)
//   2. Apply header protection to reveal the packet number length
//   3. Extract and decode the packet number
//   4. Construct the nonce: IV XOR zero-padded packet number
//   5. AEAD-decrypt the payload using the nonce and associated data (header bytes)

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

// cipherSuite identifies a QUIC cipher suite.
type cipherSuite int

const (
	cipherAES128GCM cipherSuite = iota
	cipherAES256GCM
	cipherChaCha20Poly1305
)

// cipherSuiteFromHashType infers the cipher suite from the NSS SSLHashType.
// sha256 (4) → AES-128-GCM (most common), sha384 (5) → AES-256-GCM.
// ChaCha20-Poly1305 also uses sha256 but we default to AES-128-GCM and
// retry with ChaCha20 if decryption fails.
func cipherSuiteFromHashType(hashType uint32) cipherSuite {
	switch hashType {
	case 5: // sha384
		return cipherAES256GCM
	default: // sha256 (4) or unknown
		return cipherAES128GCM
	}
}

// newAEAD creates an AEAD cipher for the given suite and key.
func newAEAD(suite cipherSuite, key []byte) (cipher.AEAD, error) {
	switch suite {
	case cipherAES128GCM, cipherAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("AES cipher: %w", err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("GCM: %w", err)
		}
		return aead, nil
	case cipherChaCha20Poly1305:
		// Use golang.org/x/crypto
		aead, err := newChaCha20Poly1305(key)
		if err != nil {
			return nil, fmt.Errorf("ChaCha20-Poly1305: %w", err)
		}
		return aead, nil
	default:
		return nil, fmt.Errorf("unsupported cipher suite: %d", suite)
	}
}

// newChaCha20Poly1305 creates a ChaCha20-Poly1305 AEAD.
func newChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}

// removeHeaderProtection removes header protection from a QUIC packet.
// Returns the packet number and the start offset of the encrypted payload.
//
// Algorithm (RFC 9001 §5.4):
//   1. Sample = packet[headerLen+4 : headerLen+4+16]
//   2. If AES: mask = AES-ECB(hp_key, sample)
//   3. Unmask first byte: pkt[0] ^= mask[0] & 0x1f (short) or 0x0f (long)
//   4. PN length = (unmasked_first_byte & 0x03) + 1
//   5. Unmask PN bytes: pkt[headerLen+i] ^= mask[1+i]
func removeHeaderProtection(packet []byte, headerLen int, hpKey []byte, suite cipherSuite) (pn int64, pnLen int, err error) {
	// Sample starts at headerLen + 4 (4 is max PN length).
	sampleOffset := headerLen + 4
	if sampleOffset+16 > len(packet) {
		return 0, 0, fmt.Errorf("packet too short for HP sample (need %d, have %d)", sampleOffset+16, len(packet))
	}
	sample := packet[sampleOffset : sampleOffset+16]

	// Compute mask.
	var mask [5]byte
	switch suite {
	case cipherAES128GCM, cipherAES256GCM:
		block, err := aes.NewCipher(hpKey)
		if err != nil {
			return 0, 0, fmt.Errorf("AES-ECB for HP: %w", err)
		}
		var encrypted [16]byte
		block.Encrypt(encrypted[:], sample)
		copy(mask[:], encrypted[:5])
	case cipherChaCha20Poly1305:
		// ChaCha20 HP: counter = sample[0:4], nonce = sample[4:16]
		counter := binary.LittleEndian.Uint32(sample[0:4])
		nonce := sample[4:16]
		stream, err := chacha20.NewUnauthenticatedCipher(hpKey, nonce)
		if err != nil {
			return 0, 0, fmt.Errorf("ChaCha20 for HP: %w", err)
		}
		stream.SetCounter(counter)
		var zeros [5]byte
		stream.XORKeyStream(mask[:], zeros[:])
	}

	// Unmask first byte.
	if packet[0]&0x80 == 0 {
		// Short header.
		packet[0] ^= mask[0] & 0x1F
	} else {
		// Long header.
		packet[0] ^= mask[0] & 0x0F
	}

	// Determine PN length from unmasked first byte.
	pnLen = int(packet[0]&0x03) + 1

	// Unmask PN bytes.
	for i := 0; i < pnLen; i++ {
		packet[headerLen+i] ^= mask[1+i]
	}

	// Decode packet number.
	pn = 0
	for i := 0; i < pnLen; i++ {
		pn = (pn << 8) | int64(packet[headerLen+i])
	}

	return pn, pnLen, nil
}

// constructNonce builds the AEAD nonce from the IV and packet number (RFC 9001 §5.3).
// nonce = IV XOR zero-padded-packet-number
func constructNonce(iv []byte, pn int64) []byte {
	nonce := make([]byte, len(iv))
	copy(nonce, iv)

	// XOR the packet number into the last 8 bytes of the nonce.
	pnBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(pnBytes, uint64(pn))
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-8+i] ^= pnBytes[i]
	}
	return nonce
}

// decryptPayload AEAD-decrypts a QUIC packet payload.
// header is the associated data (authenticated but not encrypted).
// ciphertext is the encrypted payload (including AEAD tag).
func decryptPayload(aead cipher.AEAD, nonce, header, ciphertext []byte) ([]byte, error) {
	plaintext, err := aead.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return nil, fmt.Errorf("AEAD decrypt: %w", err)
	}
	return plaintext, nil
}

// decryptShortHeaderPacket performs full decryption of a QUIC short header packet:
// header protection removal → PN decode → AEAD decrypt.
func decryptShortHeaderPacket(packet []byte, dcidLen int, keys *directionKeys, suite cipherSuite) ([]byte, int64, error) {
	headerLen := 1 + dcidLen // minimum header before PN

	// Make a working copy since header protection removal modifies in place.
	pkt := make([]byte, len(packet))
	copy(pkt, packet)

	// Remove header protection.
	pn, pnLen, err := removeHeaderProtection(pkt, headerLen, keys.hp, suite)
	if err != nil {
		return nil, 0, err
	}

	// Full header length includes the packet number.
	fullHeaderLen := headerLen + pnLen

	// Construct nonce.
	nonce := constructNonce(keys.iv, pn)

	// Decrypt.
	header := pkt[:fullHeaderLen]
	ciphertext := pkt[fullHeaderLen:]
	plaintext, err := decryptPayload(keys.aead, nonce, header, ciphertext)
	if err != nil {
		return nil, 0, err
	}

	return plaintext, pn, nil
}

// directionKeys holds keys for one direction (client→server or server→client).
type directionKeys struct {
	key  []byte
	iv   []byte
	hp   []byte
	aead cipher.AEAD
}
