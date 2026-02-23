#!/usr/bin/env bash
#
# traffic-agent.sh — start/stop/status helper for traffic-agent
#
# Usage:
#   ./traffic-agent.sh start          # start capturing, JSON → stdout, logs → stderr
#   ./traffic-agent.sh start -o out   # start in background, write to out.json / out.log
#   ./traffic-agent.sh stop           # stop background instance
#   ./traffic-agent.sh status         # show if running
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="${SCRIPT_DIR}/bin/traffic-agent"
PIDFILE="/tmp/traffic-agent.pid"

usage() {
    cat <<'EOF'
Usage: ./traffic-agent.sh <command> [options]

Commands:
  start              Run in foreground (JSON → stdout, logs → stderr)
  start -o <prefix>  Run in background, write to <prefix>.json and <prefix>.log
  stop               Stop the background instance
  status             Show whether traffic-agent is running

Examples:
  sudo ./traffic-agent.sh start                     # foreground, Ctrl+C to stop
  sudo ./traffic-agent.sh start -o /tmp/capture     # background → /tmp/capture.json + /tmp/capture.log
  sudo ./traffic-agent.sh stop                       # stop background instance
  sudo ./traffic-agent.sh status
EOF
    exit 1
}

need_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "Error: traffic-agent requires root. Run with sudo." >&2
        exit 1
    fi
}

build_if_needed() {
    if [ ! -x "$BINARY" ]; then
        echo "Binary not found, building..." >&2
        make -C "$SCRIPT_DIR" build >&2
    fi
}

do_start() {
    need_root
    build_if_needed

    # Check if already running
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        echo "traffic-agent is already running (PID $(cat "$PIDFILE"))" >&2
        exit 1
    fi

    if [ $# -ge 2 ] && [ "$1" = "-o" ]; then
        # Background mode
        local prefix="$2"
        local json_file="${prefix}.json"
        local log_file="${prefix}.log"

        "$BINARY" -v > "$json_file" 2> "$log_file" &
        local pid=$!
        echo "$pid" > "$PIDFILE"
        echo "traffic-agent started in background (PID $pid)"
        echo "  Events: $json_file"
        echo "  Logs:   $log_file"
        echo ""
        echo "Run 'sudo ./traffic-agent.sh stop' to stop."
    else
        # Foreground mode — Ctrl+C to stop
        echo "Starting traffic-agent (Ctrl+C to stop)..." >&2
        exec "$BINARY" -v
    fi
}

do_stop() {
    need_root

    if [ ! -f "$PIDFILE" ]; then
        echo "No PID file found. traffic-agent may not be running." >&2
        # Try to find and kill anyway
        if pkill -f "bin/traffic-agent" 2>/dev/null; then
            echo "Killed traffic-agent process."
        else
            echo "traffic-agent is not running."
        fi
        exit 0
    fi

    local pid
    pid=$(cat "$PIDFILE")
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid"
        # Wait up to 5s for graceful shutdown
        for i in $(seq 1 10); do
            if ! kill -0 "$pid" 2>/dev/null; then
                break
            fi
            sleep 0.5
        done
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
        echo "traffic-agent stopped (PID $pid)."
    else
        echo "traffic-agent (PID $pid) was not running."
    fi
    rm -f "$PIDFILE"
}

do_status() {
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        echo "traffic-agent is running (PID $(cat "$PIDFILE"))"
    else
        rm -f "$PIDFILE" 2>/dev/null || true
        if pgrep -f "bin/traffic-agent" > /dev/null 2>&1; then
            echo "traffic-agent is running (PID $(pgrep -f 'bin/traffic-agent'))"
        else
            echo "traffic-agent is not running."
        fi
    fi
}

[ $# -lt 1 ] && usage

case "$1" in
    start)  shift; do_start "$@" ;;
    stop)   do_stop ;;
    status) do_status ;;
    *)      usage ;;
esac
