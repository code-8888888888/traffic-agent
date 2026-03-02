// Lenient HPACK header block decoder for mid-connection join recovery.
//
// When the agent starts after an HTTP/2 connection is already established,
// the HPACK dynamic table is out of sync. The standard hpack.Decoder fails
// on the first dynamic table reference and stops. This lenient decoder
// byte-scans the HPACK block, skipping dynamic table references while
// recovering all static-table and literal header fields.
//
// Follows the same pattern as the QPACK tolerant decoder in qpack_decode.go.
// Reuses qpackReadVarInt() and qpackReadString() since HPACK and QPACK share
// the same variable-length integer and string encoding on the wire.
//
// HPACK entry types (RFC 7541 §6):
//
//	1xxxxxxx  Indexed Header Field (§6.1)                  — 7-bit prefix
//	01xxxxxx  Literal with Incremental Indexing (§6.2.1)   — 6-bit prefix
//	0000xxxx  Literal without Indexing (§6.2.2)            — 4-bit prefix
//	0001xxxx  Literal Never Indexed (§6.2.3)               — 4-bit prefix
//	001xxxxx  Dynamic Table Size Update (§6.3)             — 5-bit prefix

package parser

import (
	"log"

	"golang.org/x/net/http2/hpack"
)

// hpackStaticTable is the HPACK static table (RFC 7541 Appendix A).
// Index 0 is unused; entries 1–61 are defined.
var hpackStaticTable = [62]hpack.HeaderField{
	{},                                                    // 0: unused
	{Name: ":authority"},                                  // 1
	{Name: ":method", Value: "GET"},                       // 2
	{Name: ":method", Value: "POST"},                      // 3
	{Name: ":path", Value: "/"},                           // 4
	{Name: ":path", Value: "/index.html"},                 // 5
	{Name: ":scheme", Value: "http"},                      // 6
	{Name: ":scheme", Value: "https"},                     // 7
	{Name: ":status", Value: "200"},                       // 8
	{Name: ":status", Value: "204"},                       // 9
	{Name: ":status", Value: "206"},                       // 10
	{Name: ":status", Value: "304"},                       // 11
	{Name: ":status", Value: "400"},                       // 12
	{Name: ":status", Value: "404"},                       // 13
	{Name: ":status", Value: "500"},                       // 14
	{Name: "accept-charset"},                              // 15
	{Name: "accept-encoding", Value: "gzip, deflate"},     // 16
	{Name: "accept-language"},                             // 17
	{Name: "accept-ranges"},                               // 18
	{Name: "accept"},                                      // 19
	{Name: "access-control-allow-origin"},                 // 20
	{Name: "age"},                                         // 21
	{Name: "allow"},                                       // 22
	{Name: "authorization"},                               // 23
	{Name: "cache-control"},                               // 24
	{Name: "content-disposition"},                         // 25
	{Name: "content-encoding"},                            // 26
	{Name: "content-language"},                            // 27
	{Name: "content-length"},                              // 28
	{Name: "content-location"},                            // 29
	{Name: "content-range"},                               // 30
	{Name: "content-type"},                                // 31
	{Name: "cookie"},                                      // 32
	{Name: "date"},                                        // 33
	{Name: "etag"},                                        // 34
	{Name: "expect"},                                      // 35
	{Name: "expires"},                                     // 36
	{Name: "from"},                                        // 37
	{Name: "host"},                                        // 38
	{Name: "if-match"},                                    // 39
	{Name: "if-modified-since"},                           // 40
	{Name: "if-none-match"},                               // 41
	{Name: "if-range"},                                    // 42
	{Name: "if-unmodified-since"},                         // 43
	{Name: "last-modified"},                               // 44
	{Name: "link"},                                        // 45
	{Name: "location"},                                    // 46
	{Name: "max-forwards"},                                // 47
	{Name: "proxy-authenticate"},                          // 48
	{Name: "proxy-authorization"},                         // 49
	{Name: "range"},                                       // 50
	{Name: "referer"},                                     // 51
	{Name: "refresh"},                                     // 52
	{Name: "retry-after"},                                 // 53
	{Name: "server"},                                      // 54
	{Name: "set-cookie"},                                  // 55
	{Name: "strict-transport-security"},                   // 56
	{Name: "transfer-encoding"},                           // 57
	{Name: "user-agent"},                                  // 58
	{Name: "vary"},                                        // 59
	{Name: "via"},                                         // 60
	{Name: "www-authenticate"},                            // 61
}

// lenientDecodeHPACK decodes an HPACK header block, skipping dynamic table
// references instead of failing. Returns all recoverable header fields
// (static table lookups + literal name/value pairs).
//
// This is the key recovery mechanism for mid-connection joins where the
// standard hpack.Decoder's dynamic table is empty and fails on the first
// dynamic reference, losing all subsequent headers (including :path,
// :authority, content-type, etc.).
func lenientDecodeHPACK(block []byte) []hpack.HeaderField {
	rest := block
	var fields []hpack.HeaderField
	dynSkips := 0

	for len(rest) > 0 {
		b := rest[0]

		switch {
		case b&0x80 != 0:
			// 1xxxxxxx — Indexed Header Field (RFC 7541 §6.1)
			idx, r, err := qpackReadVarInt(7, rest)
			if err != nil {
				return fields
			}
			rest = r
			if idx >= 1 && idx <= 61 {
				fields = append(fields, hpackStaticTable[idx])
			} else {
				dynSkips++
			}

		case b&0xC0 == 0x40:
			// 01xxxxxx — Literal with Incremental Indexing (RFC 7541 §6.2.1)
			f, r, skipped := hpackDecodeLiteral(6, rest)
			if r == nil {
				return fields
			}
			rest = r
			if skipped {
				dynSkips++
			} else if f != nil {
				fields = append(fields, *f)
			}

		case b&0xE0 == 0x20:
			// 001xxxxx — Dynamic Table Size Update (RFC 7541 §6.3)
			_, r, err := qpackReadVarInt(5, rest)
			if err != nil {
				return fields
			}
			rest = r

		case b&0xF0 == 0x10:
			// 0001xxxx — Literal Never Indexed (RFC 7541 §6.2.3)
			f, r, skipped := hpackDecodeLiteral(4, rest)
			if r == nil {
				return fields
			}
			rest = r
			if skipped {
				dynSkips++
			} else if f != nil {
				fields = append(fields, *f)
			}

		case b&0xF0 == 0x00:
			// 0000xxxx — Literal without Indexing (RFC 7541 §6.2.2)
			f, r, skipped := hpackDecodeLiteral(4, rest)
			if r == nil {
				return fields
			}
			rest = r
			if skipped {
				dynSkips++
			} else if f != nil {
				fields = append(fields, *f)
			}

		default:
			return fields
		}
	}

	if dynSkips > 0 {
		log.Printf("[h2] lenient HPACK: decoded %d fields, skipped %d dynamic refs (blockLen=%d)",
			len(fields), dynSkips, len(block))
	}
	return fields
}

// hpackDecodeLiteral decodes a literal header field with the given prefix
// size for the name index.  Returns the decoded field (nil if name was from
// dynamic table), the remaining bytes, and whether a dynamic ref was skipped.
// Returns (nil, nil, false) on parse error.
func hpackDecodeLiteral(prefixBits byte, data []byte) (*hpack.HeaderField, []byte, bool) {
	idx, rest, err := qpackReadVarInt(prefixBits, data)
	if err != nil {
		return nil, nil, false
	}

	if idx == 0 {
		// Literal name + literal value.
		name, r, err := qpackReadString(rest, 7)
		if err != nil {
			return nil, nil, false
		}
		rest = r
		val, r, err := qpackReadString(rest, 7)
		if err != nil {
			return nil, nil, false
		}
		return &hpack.HeaderField{Name: name, Value: val}, r, false
	}

	// Name index > 0: read the value string.
	val, r, err := qpackReadString(rest, 7)
	if err != nil {
		return nil, nil, false
	}

	if idx >= 1 && idx <= 61 {
		// Static table name.
		return &hpack.HeaderField{
			Name:  hpackStaticTable[idx].Name,
			Value: val,
		}, r, false
	}

	// Dynamic table name reference — skip.
	return nil, r, true
}
