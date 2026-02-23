// traffic-agent: eBPF-based network traffic interception agent.
//
// The agent attaches TC (Traffic Control) eBPF programs to a network interface
// to passively capture HTTP/HTTPS traffic, and optionally attaches uprobes to
// OpenSSL to capture TLS plaintext without any certificate injection.
//
// Run with: sudo traffic-agent --config /etc/traffic-agent/config.yaml
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/traffic-agent/traffic-agent/internal/capture"
	"github.com/traffic-agent/traffic-agent/internal/config"
	"github.com/traffic-agent/traffic-agent/internal/filter"
	"github.com/traffic-agent/traffic-agent/internal/output"
	"github.com/traffic-agent/traffic-agent/internal/parser"
	"github.com/traffic-agent/traffic-agent/internal/tls"
	"github.com/traffic-agent/traffic-agent/internal/types"
)

var (
	configPath = flag.String("config", config.DefaultConfigPath, "path to config.yaml")
	verbose    = flag.Bool("v", false, "verbose logging")
)

func main() {
	flag.Parse()
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	log.Println("[main] traffic-agent starting")

	// ---- Load configuration ----
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Printf("[main] config load error (%s): %v — using defaults", *configPath, err)
		cfg = config.LoadOrDefault(*configPath)
	}
	if *verbose {
		log.Printf("[main] config: interface=%s ports=%v", cfg.Interface, cfg.Ports)
	}

	// ---- Build output layer ----
	logger, err := output.NewLogger(cfg.Output)
	if err != nil {
		log.Fatalf("[main] logger init: %v", err)
	}
	defer logger.Close()

	streamer := output.NewStreamer(cfg.EventStream)
	if err := streamer.Start(); err != nil {
		log.Fatalf("[main] event streamer start: %v", err)
	}
	defer streamer.Stop()

	// ---- Build filter ----
	f, err := filter.New(cfg.Filter)
	if err != nil {
		log.Fatalf("[main] filter init: %v", err)
	}

	// ---- Sink: write events to output ----
	sink := func(ev *types.TrafficEvent) {
		if !f.Allow(ev) {
			return
		}
		if err := logger.Write(ev); err != nil {
			log.Printf("[main] log write error: %v", err)
		}
		streamer.Publish(ev)
	}

	// ---- Build parser ----
	p := parser.New(sink)

	// ---- Start TC packet capture ----
	rawPacketCh := make(chan *types.RawPacketEvent, 512)

	cap, err := capture.New(cfg)
	if err != nil {
		log.Fatalf("[main] capturer init: %v", err)
	}
	if err := cap.Start(rawPacketCh); err != nil {
		log.Fatalf("[main] capturer start: %v", err)
	}
	defer cap.Stop()

	// Feed raw packets into the HTTP parser.
	go func() {
		for ev := range rawPacketCh {
			if f.AllowRaw(ev) {
				p.HandlePacket(ev)
			}
		}
	}()

	// Periodically flush stale TCP streams.
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			p.FlushExpired(60 * time.Second)
		}
	}()

	// ---- Start TLS interceptor (optional) ----
	if cfg.TLS.Enabled {
		sslEventCh := make(chan *types.SSLEvent, 4096)

		interceptor := tls.New(cfg.TLS)
		if err := interceptor.Start(sslEventCh); err != nil {
			log.Printf("[main] TLS interceptor start error: %v", err)
		} else {
			defer interceptor.Stop()

			go func() {
				for sslEv := range sslEventCh {
					p.HandleSSLEvent(sslEv)
				}
			}()
		}

		// Periodic SSL event stats for diagnostics.
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				rx, h2p, h2r, h1, skip := parser.SSLEventStats()
				if rx > 0 {
					log.Printf("[stats] SSL events: received=%d h2_preface=%d h2_routed=%d h1=%d skipped=%d chan_len=%d",
						rx, h2p, h2r, h1, skip, len(sslEventCh))
				}
			}
		}()
	}

	// ---- Wait for shutdown signal ----
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("[main] running — capturing on %s (ports %v)", cfg.Interface, cfg.Ports)
	log.Println("[main] press Ctrl+C to stop")

	<-ctx.Done()
	log.Println("[main] shutting down")
}
