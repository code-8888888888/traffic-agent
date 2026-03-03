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

	"github.com/traffic-agent/traffic-agent/internal/browser"
	"github.com/traffic-agent/traffic-agent/internal/capture"
	"github.com/traffic-agent/traffic-agent/internal/config"
	"github.com/traffic-agent/traffic-agent/internal/filter"
	"github.com/traffic-agent/traffic-agent/internal/output"
	"github.com/traffic-agent/traffic-agent/internal/parser"
	"github.com/traffic-agent/traffic-agent/internal/quic"
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
	if *verbose {
		parser.SetH2Debug(true)
	}

	// ---- Build QUIC / HTTP/3 pipeline ----
	h3Parser := parser.NewH3Parser(sink)
	quicProc := quic.NewProcessor(h3Parser.HandleStreamData)
	defer quicProc.Stop()

	// ---- Start TC packet capture ----
	rawPacketCh := make(chan *types.RawPacketEvent, 4096)

	cap, err := capture.New(cfg)
	if err != nil {
		log.Fatalf("[main] capturer init: %v", err)
	}
	if err := cap.Start(rawPacketCh); err != nil {
		log.Fatalf("[main] capturer start: %v", err)
	}
	defer cap.Stop()

	// Feed raw packets into the HTTP parser via 2 worker goroutines.
	// Process lookup runs here, off the ring buffer reader hot path, so a
	// slow /proc scan on one worker doesn't block the other or the reader.
	const tcWorkers = 2
	for i := 0; i < tcWorkers; i++ {
		go func() {
			for ev := range rawPacketCh {
				if !f.AllowRaw(ev) {
					continue
				}

				if ev.Protocol == 17 { // UDP
					// Fill in PID/comm for UDP.
					pid, comm := capture.LookupUDPProcessCached(
						ev.SrcIP, ev.DstIP, ev.SrcPort, ev.DstPort, uint8(ev.Direction))
					ev.PID = pid
					ev.ProcessName = comm
					quicProc.HandleUDPPacket(ev)
				} else { // TCP
					pid, comm := capture.LookupTCPProcessCached(
						ev.SrcIP, ev.DstIP, ev.SrcPort, ev.DstPort, uint8(ev.Direction))
					ev.PID = pid
					ev.ProcessName = comm
					p.HandlePacket(ev)
				}
			}
		}()
	}

	// Periodically flush stale TCP/QUIC streams and purge proc cache.
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			p.FlushExpired(60*time.Second, 30*time.Minute)
			h3Parser.FlushExpired(60 * time.Second)
			quicProc.FlushExpired(60 * time.Second)
			capture.PurgeProcCache()
		}
	}()

	// ---- Auto-configure browsers (disable QUIC for TLS interception) ----
	if cfg.TLS.Enabled && cfg.Browser.ShouldDisableQUIC() {
		if browser.IsFirefoxInstalled() {
			n, err := browser.ConfigureFirefox()
			if err != nil {
				log.Printf("[main] Firefox auto-config: %v", err)
			} else if n > 0 {
				log.Printf("[main] Firefox: QUIC disabled in %d profile(s) — HTTP/2 over TLS will be used", n)
				defer browser.RestoreFirefox()
			}
		}
	}

	// ---- Start TLS interceptor (optional) ----
	if cfg.TLS.Enabled {
		sslEventCh := make(chan *types.SSLEvent, 4096)

		interceptor := tls.New(cfg.TLS)

		// Wire QUIC key delivery: TLS interceptor → QUICKeyStore → QUICProcessor.
		interceptor.QUICKeyStore().RegisterKeyCallback(func(pid uint32, keys *tls.ConnectionKeys) {
			quicProc.RegisterKeys(pid, keys)
		})

		if err := interceptor.Start(sslEventCh); err != nil {
			log.Printf("[main] TLS interceptor start error: %v", err)
		} else {
			defer interceptor.Stop()

			// Tell the TC BPF program to skip port 443/8443 — those payloads
			// are ciphertext and the SSL uprobes capture the plaintext.
			if err := cap.SetSkipTLS(true); err != nil {
				log.Printf("[main] SetSkipTLS: %v", err)
			} else {
				log.Println("[main] TC filter: skipping TLS ports (443/8443) — SSL uprobes active")
			}

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
				sslDrops := tls.SSLDropCountReset()
				sslDedups := tls.SSLDedupCountReset()
				if rx > 0 || sslDrops > 0 || sslDedups > 0 {
					log.Printf("[stats] SSL events: received=%d h2_preface=%d h2_routed=%d h1=%d skipped=%d drops=%d dedup=%d chan_len=%d body_hits=%d h2conns=%d",
						rx, h2p, h2r, h1, skip, sslDrops, sslDedups, len(sslEventCh), parser.SSLBodyHits(), p.H2ConnCount())
				}
				h2cConns, h2cFrames := parser.H2CStats()
				if h2cConns > 0 || h2cFrames > 0 {
					log.Printf("[stats] h2c: connections=%d frames=%d", h2cConns, h2cFrames)
				}
				h2df, h2he, h2ee := parser.H2TLSStats()
				h2wr := parser.H2WriteStats()
				h2sd := parser.H2SpecDecompStats()
				if h2df > 0 || h2he > 0 || h2wr > 0 || h2sd > 0 {
					log.Printf("[stats] H2/TLS: data_frames=%d hpack_errors=%d events_emitted=%d h2_write_rejects=%d h2_spec_decomp=%d",
						h2df, h2he, h2ee, h2wr, h2sd)
				}
				sseStreams, sseChunks := parser.SSEStreamStats()
				wsConns, wsFrames := parser.WSStats()
				if sseStreams > 0 || sseChunks > 0 || wsConns > 0 || wsFrames > 0 {
					log.Printf("[stats] SSE: streams=%d chunks=%d ws_conns=%d ws_frames=%d", sseStreams, sseChunks, wsConns, wsFrames)
				}
				mcj, hexp, ldc := parser.H2StateStats()
				if mcj > 0 || hexp > 0 || ldc > 0 {
					log.Printf("[stats] H2 state: mid_conn_joins=%d states_expired=%d active=%d lenient_decodes=%d",
						mcj, hexp, p.H2ConnCount(), ldc)
				}
			}
		}()
	}

	// ---- SSLKEYLOGFILE-based QUIC key extraction (optional) ----
	if cfg.TLS.SSLKeyLogFile != "" {
		keylogWatcher := tls.NewKeylogWatcher(cfg.TLS.SSLKeyLogFile)
		keylogWatcher.RegisterKeyCallback(func(pid uint32, keys *tls.ConnectionKeys) {
			quicProc.RegisterKeys(pid, keys)
		})
		keylogWatcher.Start()
		defer keylogWatcher.Stop()
		log.Printf("[main] SSLKEYLOGFILE watcher active: %s", cfg.TLS.SSLKeyLogFile)
	}

	// Periodic TC capture stats (drop counter) + QUIC stats.
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			drops := capture.TCDropCountReset()
			if drops > 0 {
				log.Printf("[stats] TC packet drops (channel full): %d in last 5s, chan_len=%d",
					drops, len(rawPacketCh))
			}
			qConns, qRecv, qDecrypt, qFail, qH3 := quic.QUICStats()
			if qRecv > 0 || qConns > 0 {
				log.Printf("[stats] QUIC: connections=%d received=%d decrypted=%d failures=%d h3_events=%d long_hdr=%d rev_miss=%d gro=%d ku=%d",
					qConns, qRecv, qDecrypt, qFail, qH3,
					quic.QUICLongHeaderSkipped.Load(), quic.QUICReverseMisses.Load(),
					quic.QUICGROSplits.Load(), quic.QUICKeyUpdates.Load())
			}
		}
	}()

	// ---- Wait for shutdown signal ----
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("[main] running — capturing on %s (ports %v)", cfg.Interface, cfg.Ports)
	log.Println("[main] press Ctrl+C to stop")

	<-ctx.Done()
	log.Println("[main] shutting down")
}
