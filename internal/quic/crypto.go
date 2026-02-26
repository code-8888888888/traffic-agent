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
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
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

// cipherSuiteCandidates returns all cipher suites to try for a given hash type.
// SHA-256 secrets could be either AES-128-GCM or ChaCha20-Poly1305, so we
// try both. SHA-384 is always AES-256-GCM.
func cipherSuiteCandidates(hashType uint32) []cipherSuite {
	switch hashType {
	case 5: // sha384
		return []cipherSuite{cipherAES256GCM}
	default: // sha256 (4)
		return []cipherSuite{cipherAES128GCM, cipherChaCha20Poly1305}
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

	// Decode truncated packet number.
	pn = 0
	for i := 0; i < pnLen; i++ {
		pn = (pn << 8) | int64(packet[headerLen+i])
	}

	return pn, pnLen, nil
}

// reconstructPN reconstructs the full packet number from a truncated value
// using the largest successfully processed PN as context. Implements
// RFC 9000 Appendix A (DecodePacketNumber).
//
// The sender encodes only the least significant bits of the PN. The receiver
// reconstructs the full value using the highest PN it has seen so far.
func reconstructPN(truncatedPN int64, pnLen int, largestPN int64) int64 {
	pnNbits := uint(pnLen) * 8
	pnWin := int64(1) << pnNbits
	pnHwin := pnWin / 2
	pnMask := pnWin - 1

	expectedPN := largestPN + 1
	candidatePN := (expectedPN & ^pnMask) | truncatedPN

	if candidatePN <= expectedPN-pnHwin && candidatePN < (1<<62)-pnWin {
		return candidatePN + pnWin
	}
	if candidatePN > expectedPN+pnHwin && candidatePN >= pnWin {
		return candidatePN - pnWin
	}
	return candidatePN
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
// header protection removal → PN decode → PN reconstruct → AEAD decrypt.
// largestPN is the highest successfully processed PN for this direction
// (used for PN reconstruction per RFC 9000 §A). Pass -1 if unknown.
func decryptShortHeaderPacket(packet []byte, dcidLen int, keys *directionKeys, suite cipherSuite, largestPN int64) ([]byte, int64, error) {
	headerLen := 1 + dcidLen // minimum header before PN

	// Make a working copy since header protection removal modifies in place.
	pkt := make([]byte, len(packet))
	copy(pkt, packet)

	// Remove header protection.
	truncatedPN, pnLen, err := removeHeaderProtection(pkt, headerLen, keys.hp, suite)
	if err != nil {
		return nil, 0, err
	}

	// Reconstruct full packet number (RFC 9000 Appendix A).
	var pn int64
	if largestPN >= 0 {
		pn = reconstructPN(truncatedPN, pnLen, largestPN)
	} else {
		pn = truncatedPN
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

// deriveKeyUpdate derives the next generation of QUIC keys from the current
// traffic secret, per RFC 9001 §6:
//
//	updated_secret = HKDF-Expand-Label(current_secret, "quic ku", "", secret_len)
//	updated_key    = HKDF-Expand-Label(updated_secret, "quic key", "", key_len)
//	updated_iv     = HKDF-Expand-Label(updated_secret, "quic iv",  "", 12)
//
// Header protection keys are NOT updated during key update.
func deriveKeyUpdate(currentSecret []byte, hashType uint32, suite cipherSuite) (newSecret []byte, newKeys *directionKeys, err error) {
	hashFunc := hashFuncForType(hashType)
	secretLen := len(currentSecret)

	// Derive the new secret.
	newSecret, err = hkdfExpandLabelQuic(hashFunc, currentSecret, "quic ku", secretLen)
	if err != nil {
		return nil, nil, fmt.Errorf("derive ku secret: %w", err)
	}

	keyLen := keyLenForSuite(suite)
	newKey, err := hkdfExpandLabelQuic(hashFunc, newSecret, "quic key", keyLen)
	if err != nil {
		return nil, nil, fmt.Errorf("derive ku key: %w", err)
	}
	newIV, err := hkdfExpandLabelQuic(hashFunc, newSecret, "quic iv", 12)
	if err != nil {
		return nil, nil, fmt.Errorf("derive ku iv: %w", err)
	}

	aead, err := newAEAD(suite, newKey)
	if err != nil {
		return nil, nil, err
	}

	return newSecret, &directionKeys{
		key:  newKey,
		iv:   newIV,
		hp:   nil, // HP key is NOT updated
		aead: aead,
	}, nil
}

// deriveDirectionKeysFromSecrets derives complete direction keys (key, iv, hp)
// for both client and server from raw traffic secrets for a specific cipher suite.
// This is needed because different cipher suites require different key lengths
// (AES-128-GCM uses 16-byte keys, ChaCha20-Poly1305 uses 32-byte keys).
func deriveDirectionKeysFromSecrets(clientSecret, serverSecret []byte, hashFunc func() hash.Hash, keyLen int, suite cipherSuite) (*directionKeys, *directionKeys, error) {
	// Derive client keys.
	ck, err := deriveOneDirection(clientSecret, hashFunc, keyLen, suite)
	if err != nil {
		return nil, nil, fmt.Errorf("client keys: %w", err)
	}
	// Derive server keys.
	sk, err := deriveOneDirection(serverSecret, hashFunc, keyLen, suite)
	if err != nil {
		return nil, nil, fmt.Errorf("server keys: %w", err)
	}
	return ck, sk, nil
}

// deriveOneDirection derives key, iv, and hp from a single traffic secret.
func deriveOneDirection(secret []byte, hashFunc func() hash.Hash, keyLen int, suite cipherSuite) (*directionKeys, error) {
	key, err := hkdfExpandLabelQuic(hashFunc, secret, "quic key", keyLen)
	if err != nil {
		return nil, err
	}
	iv, err := hkdfExpandLabelQuic(hashFunc, secret, "quic iv", 12)
	if err != nil {
		return nil, err
	}
	hp, err := hkdfExpandLabelQuic(hashFunc, secret, "quic hp", keyLen)
	if err != nil {
		return nil, err
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

func keyLenForSuite(suite cipherSuite) int {
	switch suite {
	case cipherAES256GCM:
		return 32
	case cipherChaCha20Poly1305:
		return 32
	default:
		return 16
	}
}

func hashFuncForType(hashType uint32) func() hash.Hash {
	switch hashType {
	case 5: // sha384
		return sha512.New384
	default: // sha256
		return sha256.New
	}
}

// hkdfExpandLabelQuic implements TLS 1.3 HKDF-Expand-Label for QUIC.
func hkdfExpandLabelQuic(hashFunc func() hash.Hash, secret []byte, label string, length int) ([]byte, error) {
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
