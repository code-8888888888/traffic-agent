# traffic-agent Makefile
#
# Build targets:
#   make generate   — compile eBPF C programs into Go-embedded objects
#   make build      — build the traffic-agent binary
#   make install    — install binary + config + systemd service
#   make lint       — run golangci-lint
#   make clean      — remove build artifacts
#   make vmlinux    — regenerate bpf/headers/vmlinux.h from running kernel
#   make test       — run unit tests

BINARY     := traffic-agent
BUILD_DIR  := ./bin
CMD        := ./cmd/agent
INSTALL_BIN := /usr/local/bin/$(BINARY)
CONFIG_DIR  := /etc/traffic-agent
LOG_DIR     := /var/log/traffic-agent
SERVICE_SRC := deploy/traffic-agent.service
SERVICE_DST := /etc/systemd/system/traffic-agent.service

# Go build flags
GOFLAGS  := -v
LDFLAGS  := -ldflags "-s -w"
CGO_ENABLED := 1   # required for some gopacket layers

# eBPF compilation flags
BPF_CLANG  := clang
BPF_CFLAGS := -O2 -g -Wall -Werror -D__TARGET_ARCH_x86
BPF_INCLUDES := -I./bpf/headers

.PHONY: all generate build install uninstall lint test clean vmlinux help

all: generate build

## generate: compile eBPF C programs → Go-embedded objects (requires clang, bpf2go)
generate:
	@echo "==> Generating eBPF Go bindings"
	go generate ./internal/capture/
	go generate ./internal/tls/

## build: build the traffic-agent binary
build: generate
	@echo "==> Building $(BINARY)"
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) $(CMD)
	@echo "    Binary: $(BUILD_DIR)/$(BINARY)"

## install: install binary, config, and systemd service
install: build
	@echo "==> Installing $(BINARY)"
	install -Dm755 $(BUILD_DIR)/$(BINARY) $(INSTALL_BIN)

	@echo "==> Installing config"
	install -dm755 $(CONFIG_DIR)
	install -dm755 $(LOG_DIR)
	@if [ ! -f $(CONFIG_DIR)/config.yaml ]; then \
		install -Dm644 config/config.yaml $(CONFIG_DIR)/config.yaml; \
		echo "    Installed default config to $(CONFIG_DIR)/config.yaml"; \
	else \
		echo "    Config already exists at $(CONFIG_DIR)/config.yaml — skipping"; \
	fi

	@echo "==> Installing systemd service"
	install -Dm644 $(SERVICE_SRC) $(SERVICE_DST)
	systemctl daemon-reload
	@echo "    Installed $(SERVICE_DST)"
	@echo "    To enable and start: sudo systemctl enable --now traffic-agent"

## uninstall: remove installed files and service
uninstall:
	systemctl stop traffic-agent 2>/dev/null || true
	systemctl disable traffic-agent 2>/dev/null || true
	rm -f $(INSTALL_BIN)
	rm -f $(SERVICE_DST)
	systemctl daemon-reload
	@echo "Config and logs left intact in $(CONFIG_DIR) and $(LOG_DIR)"

## lint: run golangci-lint (install: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
lint:
	golangci-lint run ./...

## test: run unit tests
test:
	go test -v -race ./...

## vmlinux: regenerate bpf/headers/vmlinux.h from the running kernel's BTF
vmlinux:
	@echo "==> Generating vmlinux.h from /sys/kernel/btf/vmlinux"
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/headers/vmlinux.h
	@echo "    Written to bpf/headers/vmlinux.h"

## tidy: run go mod tidy
tidy:
	go mod tidy

## clean: remove build artifacts and generated eBPF bindings
clean:
	rm -rf $(BUILD_DIR)
	rm -f internal/capture/tccapture_bpf*.go
	rm -f internal/capture/tccapture_bpf*.o
	rm -f internal/tls/ssluprobe_bpf*.go
	rm -f internal/tls/ssluprobe_bpf*.o

## help: show this help
help:
	@grep -E '^## ' Makefile | sed 's/## /  /'
