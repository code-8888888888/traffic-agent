// Package types defines the shared data structures that flow through the
// traffic-agent pipeline from capture → parser → filter → output.
package types

import (
	"net"
	"time"
)

// Direction indicates the flow direction of a captured packet.
type Direction uint8

const (
	DirectionIngress Direction = 0
	DirectionEgress  Direction = 1
)

func (d Direction) String() string {
	if d == DirectionIngress {
		return "ingress"
	}
	return "egress"
}

// RawPacketEvent is the low-level event emitted by the TC eBPF program.
// It is produced by the capture package and consumed by the parser package.
type RawPacketEvent struct {
	TimestampNS uint64
	SrcIP       net.IP
	DstIP       net.IP
	SrcPort     uint16
	DstPort     uint16
	Direction   Direction
	Protocol    uint8
	// PID and ProcessName are populated for egress packets (process context).
	// For ingress packets (softirq context), PID is 0 and ProcessName is empty.
	PID         uint32
	ProcessName string
	Payload     []byte
}

// SSLEvent is the plaintext data event emitted by the SSL uprobe eBPF program.
// It is produced by the tls package and consumed by the parser package.
type SSLEvent struct {
	TimestampNS uint64
	PID         uint32
	TID         uint32
	UID         uint32
	IsRead      bool   // true = SSL_read (received), false = SSL_write (sent)
	ProcessName string
	Data        []byte
}

// TrafficEvent is the fully-parsed, enriched event that flows to the output
// layer. Fields are populated progressively as the event moves through the
// pipeline; unpopulated fields retain their zero values.
type TrafficEvent struct {
	// Core metadata
	Timestamp   time.Time `json:"timestamp"`
	SrcIP       string    `json:"src_ip"`
	DstIP       string    `json:"dst_ip"`
	SrcPort     uint16    `json:"src_port"`
	DstPort     uint16    `json:"dst_port"`
	Protocol    string    `json:"protocol"`
	Direction   string    `json:"direction"`

	// Process context (best-effort; may be empty for kernel-level capture)
	PID         uint32 `json:"pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`

	// HTTP layer (populated when HTTP/1.1 traffic is detected)
	HTTPMethod      string            `json:"http_method,omitempty"`
	URL             string            `json:"url,omitempty"`
	StatusCode      int               `json:"status_code,omitempty"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`

	// Payload snippet (first 512 bytes of the HTTP body or raw payload)
	BodySnippet string `json:"body_snippet,omitempty"`

	// RequestBody holds the full POST/PUT/PATCH request body (up to 4096 bytes).
	RequestBody string `json:"request_body,omitempty"`

	// TLSIntercepted indicates the payload came from an SSL uprobe (plaintext).
	TLSIntercepted bool `json:"tls_intercepted,omitempty"`
}

const BodySnippetMaxLen = 512
const RequestBodyMaxLen = 4096
