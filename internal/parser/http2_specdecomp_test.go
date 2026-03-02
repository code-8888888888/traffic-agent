package parser

import (
	"bytes"
	"compress/gzip"
	"testing"

	"github.com/andybalholm/brotli"
)

func compressBrotli(data []byte) []byte {
	var buf bytes.Buffer
	w := brotli.NewWriterLevel(&buf, 4)
	w.Write(data)
	w.Close()
	return buf.Bytes()
}

func compressGzip(data []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(data)
	w.Close()
	return buf.Bytes()
}

func TestLooksCompressed(t *testing.T) {
	plain := []byte(`event: message_start\r\ndata: {"type":"message_start"}\r\n`)
	br := compressBrotli(plain)
	gz := compressGzip(plain)

	if looksCompressed(plain) {
		t.Error("plaintext should not look compressed")
	}
	if !looksCompressed(br) {
		t.Error("brotli data should look compressed")
	}
	if !looksCompressed(gz) {
		t.Error("gzip data should look compressed")
	}
	if looksCompressed([]byte("ab")) {
		t.Error("short data should not look compressed")
	}
	// JSON should not look compressed
	if looksCompressed([]byte(`{"type":"message","content":"Hello world"}`)) {
		t.Error("JSON should not look compressed")
	}
}

func TestTryDecompress(t *testing.T) {
	sseData := []byte("event: message_start\r\ndata: {\"type\":\"message_start\"}\r\n\r\n")

	tests := []struct {
		name    string
		data    []byte
		wantEnc string
	}{
		{"brotli", compressBrotli(sseData), "br"},
		{"gzip", compressGzip(sseData), "gzip"},
		{"plaintext", sseData, ""},
		{"random", []byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tryDecompress(tt.data)
			if got != tt.wantEnc {
				t.Errorf("tryDecompress(%s) = %q, want %q", tt.name, got, tt.wantEnc)
			}
		})
	}
}

func TestTryDecompressAccumulation(t *testing.T) {
	// Simulate multiple DATA frames accumulating in compressedBuf.
	// After enough data accumulates, tryDecompress should succeed.
	sseData := []byte("event: message_start\r\ndata: {\"type\":\"message_start\"}\r\n\r\nevent: content_block_delta\r\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"text\":\"Hello\"}}\r\n\r\n")
	br := compressBrotli(sseData)

	// Split into ~3 "DATA frames"
	chunkSize := len(br) / 3
	var compressedBuf []byte
	detected := ""

	for i := 0; i < 3; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if i == 2 {
			end = len(br) // last chunk gets remainder
		}
		chunk := br[start:end]
		compressedBuf = append(compressedBuf, chunk...)
		detected = tryDecompress(compressedBuf)
		if detected != "" {
			break
		}
	}

	if detected != "br" {
		t.Errorf("after accumulating all chunks: tryDecompress = %q, want \"br\"", detected)
	}
}

func TestSpeculativeDecompCaching(t *testing.T) {
	// Simulate the processDataFrame flow: first frame detects encoding,
	// second frame uses cached detectedEncoding.
	sseData := []byte("event: message_start\r\ndata: {\"type\":\"message_start\"}\r\n\r\n")
	br := compressBrotli(sseData)

	info := &h2StreamInfo{statusCode: 200}

	// First DATA frame: full compressed data
	info.compressedBuf = append(info.compressedBuf, br...)
	detected := tryDecompress(info.compressedBuf)
	if detected == "" {
		t.Fatal("first frame: tryDecompress should detect brotli")
	}
	info.detectedEncoding = detected

	if info.detectedEncoding != "br" {
		t.Errorf("detectedEncoding = %q, want \"br\"", info.detectedEncoding)
	}

	// Verify the encoding fallback logic (mirrors processDataFrame)
	encoding := info.contentEncoding
	if encoding == "" {
		encoding = info.detectedEncoding
	}
	if encoding != "br" {
		t.Errorf("encoding fallback = %q, want \"br\"", encoding)
	}
}

func TestLooksCompressedThreshold(t *testing.T) {
	// Exactly at the 30% boundary
	data := make([]byte, 100)
	// Fill with printable ASCII
	for i := range data {
		data[i] = 'A'
	}
	if looksCompressed(data) {
		t.Error("all-printable should not look compressed")
	}

	// Set 31% to non-printable (in first 64 bytes)
	for i := 0; i < 20; i++ {
		data[i] = 0x80
	}
	// 20/64 = 31.25% > 30%
	if !looksCompressed(data) {
		t.Error("31% non-printable should look compressed")
	}
}
