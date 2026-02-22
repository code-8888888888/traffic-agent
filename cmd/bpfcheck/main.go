// bpfcheck loads the TC capture eBPF program and prints the full verifier log.
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/traffic-agent/traffic-agent/internal/capture"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "memlock: %v\n", err)
	}

	var objs capture.TCCaptureObjects
	err := capture.LoadTCCaptureObjects(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
			LogSize:  1 << 24, // 16 MiB
		},
	})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			fmt.Fprintln(os.Stderr, "=== VERIFIER LOG ===")
			fmt.Fprintln(os.Stderr, strings.Join(ve.Log, "\n"))
			fmt.Fprintln(os.Stderr, "=== END LOG ===")
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	objs.Close()
	fmt.Println("OK: BPF programs loaded successfully")
}
