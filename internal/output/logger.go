// Package output handles structured JSON event logging and HTTP event streaming.
package output

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"sync"

	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/traffic-agent/traffic-agent/internal/config"
	"github.com/traffic-agent/traffic-agent/internal/types"
)

// Logger writes TrafficEvents as newline-delimited JSON to one or more
// configured destinations (stdout, rotating file).
type Logger struct {
	mu      sync.Mutex
	writers []io.Writer
	enc     *json.Encoder
}

// NewLogger constructs a Logger based on the OutputConfig.
func NewLogger(cfg config.OutputConfig) (*Logger, error) {
	var writers []io.Writer

	if cfg.Stdout {
		writers = append(writers, os.Stdout)
	}

	if cfg.File != "" {
		rotator := &lumberjack.Logger{
			Filename:   cfg.File,
			MaxSize:    cfg.MaxSizeMB,  // megabytes
			MaxAge:     cfg.MaxAgeDays, // days
			MaxBackups: cfg.MaxBackups,
			Compress:   cfg.Compress,
		}
		writers = append(writers, rotator)
	}

	if len(writers) == 0 {
		log.Println("[output] no output destination configured; defaulting to stdout")
		writers = append(writers, os.Stdout)
	}

	mw := io.MultiWriter(writers...)
	enc := json.NewEncoder(mw)

	return &Logger{
		writers: writers,
		enc:     enc,
	}, nil
}

// Write encodes ev as a JSON line and writes it to all configured destinations.
// It is safe to call from multiple goroutines.
func (l *Logger) Write(ev *types.TrafficEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.enc.Encode(ev)
}

// Close flushes and closes any file-based writers.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	var lastErr error
	for _, w := range l.writers {
		if c, ok := w.(io.Closer); ok {
			if err := c.Close(); err != nil {
				lastErr = err
			}
		}
	}
	return lastErr
}
