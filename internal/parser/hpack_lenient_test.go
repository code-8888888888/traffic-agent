package parser

import (
	"testing"

	"golang.org/x/net/http2/hpack"
)

// TestLenientDecodeHPACK_StaticOnly verifies that purely static-table
// indexed headers are decoded correctly.
func TestLenientDecodeHPACK_StaticOnly(t *testing.T) {
	// Build an HPACK block with:
	//   :method GET  (indexed 2)
	//   :path /      (indexed 4)
	//   :scheme https (indexed 7)
	block := []byte{
		0x82, // indexed 2 → :method GET
		0x84, // indexed 4 → :path /
		0x87, // indexed 7 → :scheme https
	}

	fields := lenientDecodeHPACK(block)
	if len(fields) != 3 {
		t.Fatalf("expected 3 fields, got %d", len(fields))
	}
	expect := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/"},
		{Name: ":scheme", Value: "https"},
	}
	for i, f := range fields {
		if f.Name != expect[i].Name || f.Value != expect[i].Value {
			t.Errorf("field %d: got %q=%q, want %q=%q", i, f.Name, f.Value, expect[i].Name, expect[i].Value)
		}
	}
}

// TestLenientDecodeHPACK_DynamicSkipped verifies that dynamic table
// references are skipped and subsequent static/literal fields are recovered.
func TestLenientDecodeHPACK_DynamicSkipped(t *testing.T) {
	// Build a block that simulates mid-connection join:
	//   dynamic index 62 (0xBE = 1_0111110)  → should be SKIPPED
	//   :method POST (indexed 3, 0x83)        → should be RECOVERED
	//   dynamic index 63 (0xBF = 1_0111111)  → should be SKIPPED
	//   :path /      (indexed 4, 0x84)        → should be RECOVERED
	block := []byte{
		0xBE, // indexed 62 → dynamic, skip
		0x83, // indexed 3  → :method POST
		0xBF, // indexed 63 → dynamic, skip
		0x84, // indexed 4  → :path /
	}

	fields := lenientDecodeHPACK(block)
	if len(fields) != 2 {
		t.Fatalf("expected 2 fields, got %d: %+v", len(fields), fields)
	}
	if fields[0].Name != ":method" || fields[0].Value != "POST" {
		t.Errorf("field 0: got %q=%q, want :method=POST", fields[0].Name, fields[0].Value)
	}
	if fields[1].Name != ":path" || fields[1].Value != "/" {
		t.Errorf("field 1: got %q=%q, want :path=/", fields[1].Name, fields[1].Value)
	}
}

// TestLenientDecodeHPACK_LiteralFields verifies that literal name/value
// pairs (both with static name ref and fully literal) are decoded.
func TestLenientDecodeHPACK_LiteralFields(t *testing.T) {
	// Literal with incremental indexing, name index 1 (:authority), value "example.com"
	// 0x41 = 01_000001 (incremental indexing, name index 1)
	// Then string: 0x0b "example.com" (length 11, no Huffman)
	block := []byte{
		0x41,                                                                         // literal w/ indexing, name idx 1 (:authority)
		0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',               // value "example.com"
		0x40,                                                                         // literal w/ indexing, name idx 0 (literal name)
		0x0a, 'x', '-', 'c', 'u', 's', 't', 'o', 'm', '-', 'h',                     // name "x-custom-h"
		0x05, 'v', 'a', 'l', 'u', 'e',                                               // value "value"
	}

	fields := lenientDecodeHPACK(block)
	if len(fields) != 2 {
		t.Fatalf("expected 2 fields, got %d: %+v", len(fields), fields)
	}
	if fields[0].Name != ":authority" || fields[0].Value != "example.com" {
		t.Errorf("field 0: got %q=%q, want :authority=example.com", fields[0].Name, fields[0].Value)
	}
	if fields[1].Name != "x-custom-h" || fields[1].Value != "value" {
		t.Errorf("field 1: got %q=%q, want x-custom-h=value", fields[1].Name, fields[1].Value)
	}
}

// TestLenientDecodeHPACK_MixedWithDynamic simulates a real mid-connection
// join HPACK block where dynamic refs are interspersed with static and
// literal fields — exactly the scenario the lenient decoder is designed for.
func TestLenientDecodeHPACK_MixedWithDynamic(t *testing.T) {
	// Simulated HPACK block for a claude.ai completion request:
	//   dynamic index 62  → :authority claude.ai (in dynamic table, SKIP)
	//   :method POST      → static index 3
	//   dynamic index 63  → some-cookie (in dynamic table, SKIP)
	//   literal w/ indexing, name idx 0, name=":path", value="/api/completion"
	//   dynamic index 64  → another header (SKIP)
	//   literal w/ indexing, name idx 31 (content-type), value="application/json"
	block := []byte{
		0xBE,       // dynamic idx 62 → SKIP
		0x83,       // static idx 3 → :method POST
		0xBF,       // dynamic idx 63 → SKIP
		0xC0,       // dynamic idx 64 → SKIP (multi-byte: 0x80 | 0x40 = 0xC0... wait)
	}
	// Actually 0xC0 = 1_1000000 = indexed, index = 64 (7-bit prefix: 1_0000000 mask = 0x7F, value = 0x40 = 64)
	// That's correct for dynamic index 64.

	// Literal with incremental indexing, literal name ":path", value "/api/completion"
	pathEntry := []byte{
		0x40,                                                                                  // literal w/ indexing, idx 0
		0x05, ':', 'p', 'a', 't', 'h',                                                        // name ":path"
		0x0f, '/', 'a', 'p', 'i', '/', 'c', 'o', 'm', 'p', 'l', 'e', 't', 'i', 'o', 'n',    // value "/api/completion"
	}
	block = append(block, pathEntry...)

	// Literal with incremental indexing, name idx 31 (content-type), value "application/json"
	// 0x5F = 01_011111 → 6-bit prefix value 31, fits without continuation
	ctEntry := []byte{
		0x5f, // literal w/ indexing, idx 31 (content-type)
		0x10, 'a', 'p', 'p', 'l', 'i', 'c', 'a', 't', 'i', 'o', 'n', '/', 'j', 's', 'o', 'n',
	}
	block = append(block, ctEntry...)

	fields := lenientDecodeHPACK(block)

	// Should recover: :method POST, :path /api/completion, content-type application/json
	// Should skip: 3 dynamic refs (indices 62, 63, 64)
	if len(fields) != 3 {
		t.Fatalf("expected 3 fields, got %d: %+v", len(fields), fields)
	}

	got := make(map[string]string)
	for _, f := range fields {
		got[f.Name] = f.Value
	}
	if got[":method"] != "POST" {
		t.Errorf(":method = %q, want POST", got[":method"])
	}
	if got[":path"] != "/api/completion" {
		t.Errorf(":path = %q, want /api/completion", got[":path"])
	}
	if got["content-type"] != "application/json" {
		t.Errorf("content-type = %q, want application/json", got["content-type"])
	}
}

// TestLenientDecodeHPACK_DynNameRef verifies that literal fields with
// dynamic table name references have their values skipped correctly.
func TestLenientDecodeHPACK_DynNameRef(t *testing.T) {
	// Literal with incremental indexing, name from dynamic index 62
	// 0x7E = 01_111110 → incremental indexing, name index = 62 (dynamic → skip)
	// Followed by value string "some-value"
	block := []byte{
		0x7E,                                                         // literal w/ indexing, name idx 62 (dynamic)
		0x0a, 's', 'o', 'm', 'e', '-', 'v', 'a', 'l', 'u', 'e',    // value
		0x82, // static idx 2 → :method GET (should still be recovered)
	}

	fields := lenientDecodeHPACK(block)
	if len(fields) != 1 {
		t.Fatalf("expected 1 field, got %d: %+v", len(fields), fields)
	}
	if fields[0].Name != ":method" || fields[0].Value != "GET" {
		t.Errorf("field 0: got %q=%q, want :method=GET", fields[0].Name, fields[0].Value)
	}
}

// TestLenientDecodeHPACK_TableSizeUpdate verifies that dynamic table
// size updates are silently skipped.
func TestLenientDecodeHPACK_TableSizeUpdate(t *testing.T) {
	// Table size update to 4096: 001_00000 + continuation
	// 0x3F 0xE1 0x1F = 5-bit prefix: 31 + (0x61 & 0x7F)<<0 = 31 + 97 = 128... actually
	// Let's use a simpler encoding: 0x20 = table size update to 0
	block := []byte{
		0x20, // table size update, new size = 0
		0x82, // indexed 2 → :method GET
	}

	fields := lenientDecodeHPACK(block)
	if len(fields) != 1 {
		t.Fatalf("expected 1 field, got %d: %+v", len(fields), fields)
	}
	if fields[0].Name != ":method" || fields[0].Value != "GET" {
		t.Errorf("got %q=%q, want :method=GET", fields[0].Name, fields[0].Value)
	}
}

// TestLenientDecodeHPACK_EmptyBlock verifies empty input returns nil.
func TestLenientDecodeHPACK_EmptyBlock(t *testing.T) {
	fields := lenientDecodeHPACK(nil)
	if len(fields) != 0 {
		t.Fatalf("expected 0 fields, got %d", len(fields))
	}
	fields = lenientDecodeHPACK([]byte{})
	if len(fields) != 0 {
		t.Fatalf("expected 0 fields, got %d", len(fields))
	}
}
