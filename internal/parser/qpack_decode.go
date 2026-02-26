// Tolerant QPACK header block decoder.
//
// The standard quic-go/qpack library rejects any header block that references
// the dynamic table (Required Insert Count > 0). In practice, many servers
// (e.g., Google) use dynamic table entries for common response headers.
//
// This custom decoder:
//   - Accepts any Required Insert Count / Delta Base prefix
//   - Decodes static table references and literal name/value pairs normally
//   - Skips dynamic table references (indexed or name-reference) gracefully
//   - Returns as many decoded headers as possible
//
// Field line types (RFC 9204 §4.5):
//
//	1xxxxxxx  Indexed Field Line         (T bit = static vs dynamic)
//	01xxxxxx  Literal with Name Reference (T bit = static vs dynamic)
//	001xxxxx  Literal without Name Reference
//	0001xxxx  Indexed with Post-Base Index (always dynamic)
//	0000xxxx  Literal with Post-Base Name Reference (always dynamic)

package parser

import (
	"io"

	"golang.org/x/net/http2/hpack"
)

// qpackHeaderField is a decoded header name/value pair.
type qpackHeaderField struct {
	Name  string
	Value string
}

// qpackStaticTable is the QPACK static table (RFC 9204 Appendix A).
// 99 entries indexed 0-98.
var qpackStaticTable = [99]qpackHeaderField{
	{":authority", ""},
	{":path", "/"},
	{"age", "0"},
	{"content-disposition", ""},
	{"content-length", "0"},
	{"cookie", ""},
	{"date", ""},
	{"etag", ""},
	{"if-modified-since", ""},
	{"if-none-match", ""},
	{"last-modified", ""},
	{"link", ""},
	{"location", ""},
	{"referer", ""},
	{"set-cookie", ""},
	{":method", "CONNECT"},
	{":method", "DELETE"},
	{":method", "GET"},
	{":method", "HEAD"},
	{":method", "OPTIONS"},
	{":method", "POST"},
	{":method", "PUT"},
	{":scheme", "http"},
	{":scheme", "https"},
	{":status", "103"},
	{":status", "200"},
	{":status", "304"},
	{":status", "404"},
	{":status", "503"},
	{"accept", "*/*"},
	{"accept", "application/dns-message"},
	{"accept-encoding", "gzip, deflate, br"},
	{"accept-ranges", "bytes"},
	{"access-control-allow-headers", "cache-control"},
	{"access-control-allow-headers", "content-type"},
	{"access-control-allow-origin", "*"},
	{"cache-control", "max-age=0"},
	{"cache-control", "max-age=2592000"},
	{"cache-control", "max-age=604800"},
	{"cache-control", "no-cache"},
	{"cache-control", "no-store"},
	{"cache-control", "public, max-age=31536000"},
	{"content-encoding", "br"},
	{"content-encoding", "gzip"},
	{"content-type", "application/dns-message"},
	{"content-type", "application/javascript"},
	{"content-type", "application/json"},
	{"content-type", "application/x-www-form-urlencoded"},
	{"content-type", "image/gif"},
	{"content-type", "image/jpeg"},
	{"content-type", "image/png"},
	{"content-type", "text/css"},
	{"content-type", "text/html; charset=utf-8"},
	{"content-type", "text/plain"},
	{"content-type", "text/plain;charset=utf-8"},
	{"range", "bytes=0-"},
	{"strict-transport-security", "max-age=31536000"},
	{"strict-transport-security", "max-age=31536000; includesubdomains"},
	{"strict-transport-security", "max-age=31536000; includesubdomains; preload"},
	{"vary", "accept-encoding"},
	{"vary", "origin"},
	{"x-content-type-options", "nosniff"},
	{"x-xss-protection", "1; mode=block"},
	{":status", "100"},
	{":status", "204"},
	{":status", "206"},
	{":status", "302"},
	{":status", "400"},
	{":status", "403"},
	{":status", "421"},
	{":status", "425"},
	{":status", "500"},
	{"accept-language", ""},
	{"access-control-allow-credentials", "FALSE"},
	{"access-control-allow-credentials", "TRUE"},
	{"access-control-allow-headers", "*"},
	{"access-control-allow-methods", "get"},
	{"access-control-allow-methods", "get, post, options"},
	{"access-control-allow-methods", "options"},
	{"access-control-expose-headers", "content-length"},
	{"access-control-request-headers", "content-type"},
	{"access-control-request-method", "get"},
	{"access-control-request-method", "post"},
	{"alt-svc", "clear"},
	{"authorization", ""},
	{"content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"},
	{"early-data", "1"},
	{"expect-ct", ""},
	{"forwarded", ""},
	{"if-range", ""},
	{"origin", ""},
	{"purpose", "prefetch"},
	{"server", ""},
	{"timing-allow-origin", "*"},
	{"upgrade-insecure-requests", "1"},
	{"user-agent", ""},
	{"x-forwarded-for", ""},
	{"x-frame-options", "deny"},
	{"x-frame-options", "sameorigin"},
}

// qpackDecode decodes a QPACK header block, tolerating dynamic table references.
// Returns all successfully decoded header fields (static table + literals).
// Dynamic table references are silently skipped.
func qpackDecode(data []byte) []qpackHeaderField {
	if len(data) < 2 {
		return nil
	}

	// Read Required Insert Count (8-bit prefix integer) — accept any value.
	_, rest, err := qpackReadVarInt(8, data)
	if err != nil {
		return nil
	}

	// Read Delta Base (7-bit prefix integer) — accept any value.
	_, rest, err = qpackReadVarInt(7, rest)
	if err != nil {
		return nil
	}

	var fields []qpackHeaderField

	for len(rest) > 0 {
		b := rest[0]
		switch {
		case b&0x80 != 0:
			// 1xxxxxxx — Indexed Field Line
			// T bit (0x40): 1=static, 0=dynamic
			if b&0x40 != 0 {
				// Static table reference.
				idx, r, err := qpackReadVarInt(6, rest)
				if err != nil {
					return fields
				}
				rest = r
				if idx < uint64(len(qpackStaticTable)) {
					fields = append(fields, qpackStaticTable[idx])
				}
			} else {
				// Dynamic table reference — skip.
				_, r, err := qpackReadVarInt(6, rest)
				if err != nil {
					return fields
				}
				rest = r
			}

		case b&0xC0 == 0x40:
			// 01xxxxxx — Literal with Name Reference
			// T bit (0x10): 1=static, 0=dynamic
			if b&0x10 != 0 {
				// Name from static table, value is literal.
				idx, r, err := qpackReadVarInt(4, rest)
				if err != nil {
					return fields
				}
				rest = r
				val, r, err := qpackReadString(rest, 7)
				if err != nil {
					return fields
				}
				rest = r
				if idx < uint64(len(qpackStaticTable)) {
					fields = append(fields, qpackHeaderField{
						Name:  qpackStaticTable[idx].Name,
						Value: val,
					})
				}
			} else {
				// Name from dynamic table — skip name index + value string.
				_, r, err := qpackReadVarInt(4, rest)
				if err != nil {
					return fields
				}
				rest = r
				_, r, err = qpackReadString(rest, 7)
				if err != nil {
					return fields
				}
				rest = r
			}

		case b&0xE0 == 0x20:
			// 001xxxxx — Literal without Name Reference
			// Name and value are both literal strings.
			name, r, err := qpackReadString(rest, 3)
			if err != nil {
				return fields
			}
			rest = r
			val, r, err := qpackReadString(rest, 7)
			if err != nil {
				return fields
			}
			rest = r
			fields = append(fields, qpackHeaderField{Name: name, Value: val})

		case b&0xF0 == 0x10:
			// 0001xxxx — Indexed with Post-Base Index (always dynamic)
			_, r, err := qpackReadVarInt(4, rest)
			if err != nil {
				return fields
			}
			rest = r

		case b&0xF0 == 0x00:
			// 0000xxxx — Literal with Post-Base Name Reference (always dynamic)
			_, r, err := qpackReadVarInt(3, rest)
			if err != nil {
				return fields
			}
			rest = r
			_, r, err = qpackReadString(rest, 7)
			if err != nil {
				return fields
			}
			rest = r

		default:
			// Unknown — stop parsing.
			return fields
		}
	}

	return fields
}

// qpackReadVarInt reads an HPACK/QPACK variable-length integer with n-bit prefix.
func qpackReadVarInt(n byte, p []byte) (uint64, []byte, error) {
	if len(p) == 0 {
		return 0, p, io.ErrUnexpectedEOF
	}
	mask := uint64((1 << n) - 1)
	i := uint64(p[0]) & mask
	if i < mask {
		return i, p[1:], nil
	}
	p = p[1:]
	var m uint64
	for len(p) > 0 {
		b := p[0]
		p = p[1:]
		i += uint64(b&127) << m
		if b&128 == 0 {
			return i, p, nil
		}
		m += 7
		if m >= 63 {
			return 0, nil, io.ErrUnexpectedEOF
		}
	}
	return 0, nil, io.ErrUnexpectedEOF
}

// qpackReadString reads an HPACK/QPACK length-prefixed string with n-bit prefix.
// Bit 7 of the first byte indicates Huffman encoding.
func qpackReadString(p []byte, n byte) (string, []byte, error) {
	if len(p) == 0 {
		return "", nil, io.ErrUnexpectedEOF
	}
	usesHuffman := p[0]&(1<<(n))>>n != 0
	// Special case: for n=3, Huffman flag is bit 3 (0x08).
	if n == 3 {
		usesHuffman = p[0]&0x08 != 0
	} else if n == 7 {
		usesHuffman = p[0]&0x80 != 0
	}
	length, rest, err := qpackReadVarInt(n, p)
	if err != nil {
		return "", nil, err
	}
	if uint64(len(rest)) < length {
		return "", nil, io.ErrUnexpectedEOF
	}
	raw := rest[:length]
	rest = rest[length:]
	if usesHuffman {
		s, err := hpack.HuffmanDecodeToString(raw)
		if err != nil {
			return "", rest, err
		}
		return s, rest, nil
	}
	return string(raw), rest, nil
}
