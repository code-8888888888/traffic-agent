package output

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/traffic-agent/traffic-agent/internal/config"
	"github.com/traffic-agent/traffic-agent/internal/types"
)

// Streamer exposes a long-lived HTTP endpoint that pushes TrafficEvents to
// connected clients as newline-delimited JSON (ndjson / Server-Sent Events
// style). Clients connect once and receive all subsequent events.
type Streamer struct {
	cfg     config.StreamConfig
	mu      sync.RWMutex
	clients map[chan []byte]struct{}
	server  *http.Server
}

// NewStreamer creates (but does not start) an event streaming server.
func NewStreamer(cfg config.StreamConfig) *Streamer {
	s := &Streamer{
		cfg:     cfg,
		clients: make(map[chan []byte]struct{}),
	}
	return s
}

// Start begins listening. It returns immediately; the HTTP server runs in a
// background goroutine. Call Stop to shut it down.
func (s *Streamer) Start() error {
	if !s.cfg.Enabled {
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc(s.cfg.Path, s.handleStream)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	s.server = &http.Server{
		Addr:    s.cfg.Address,
		Handler: mux,
	}

	go func() {
		log.Printf("[stream] listening on http://%s%s", s.cfg.Address, s.cfg.Path)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[stream] server error: %v", err)
		}
	}()

	return nil
}

// Publish sends an event to all currently connected streaming clients.
// It is safe to call from multiple goroutines.
func (s *Streamer) Publish(ev *types.TrafficEvent) {
	if !s.cfg.Enabled {
		return
	}

	data, err := json.Marshal(ev)
	if err != nil {
		log.Printf("[stream] marshal error: %v", err)
		return
	}
	line := append(data, '\n')

	s.mu.RLock()
	defer s.mu.RUnlock()

	for ch := range s.clients {
		// Non-blocking send: drop the event for slow clients rather than
		// blocking the producer goroutine.
		select {
		case ch <- line:
		default:
		}
	}
}

// Stop gracefully shuts down the HTTP server.
func (s *Streamer) Stop() error {
	if s.server == nil {
		return nil
	}
	return s.server.Close()
}

// handleStream services a single long-lived streaming connection.
func (s *Streamer) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan []byte, 64)
	s.addClient(ch)
	defer s.removeClient(ch)

	log.Printf("[stream] client connected: %s", r.RemoteAddr)
	defer log.Printf("[stream] client disconnected: %s", r.RemoteAddr)

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case line, ok := <-ch:
			if !ok {
				return
			}
			if _, err := w.Write(line); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Streamer) addClient(ch chan []byte) {
	s.mu.Lock()
	s.clients[ch] = struct{}{}
	s.mu.Unlock()
}

func (s *Streamer) removeClient(ch chan []byte) {
	s.mu.Lock()
	delete(s.clients, ch)
	close(ch)
	s.mu.Unlock()
}
