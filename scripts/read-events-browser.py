#!/usr/bin/env python3
"""Reconstruct captured browser (claude.ai) responses from events.json.

Reads NDJSON events produced by traffic-agent and reconstructs full
responses from the browser's SSE completion stream. The browser uses
HTTP/2 over TLS via /api/organizations/.../completion. Due to H2
mid-connection joins, response SSE chunks may arrive without a URL,
so this script also collects URL-less ingress events containing SSE data.

Handles duplicate events (NSS read+return probes capture the same data
twice) by deduplicating consecutive identical body_snippet values.

Usage:
    ./scripts/read-events-browser.py                          # last response
    ./scripts/read-events-browser.py --all                    # all responses
    ./scripts/read-events-browser.py --raw                    # show all event details
    ./scripts/read-events-browser.py -f /path/to/events.json  # custom file
"""

import argparse
import json
import sys


def load_events(path):
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def find_completion_groups(events):
    """Find browser completion request/response groups.

    Groups are formed around POST /completion egress events. The SSE
    response chunks may arrive as:
      1. Ingress events with the /completion URL (ideal case)
      2. Ingress events with no URL but containing SSE data (H2 mid-join)

    For case 2, we collect URL-less SSE ingress events that appear
    between this completion POST and the next egress request.
    """
    groups = []
    current_req = None
    current_events = []

    for ev in events:
        url = ev.get("url", "")
        direction = ev.get("direction", "")
        body = ev.get("body_snippet", "")

        # New completion POST request starts a group.
        if direction == "egress" and "completion" in url and ev.get("http_method") == "POST":
            if current_req is not None:
                groups.append((current_req, current_events))
            current_req = ev
            current_events = []
            continue

        # Collect ingress SSE events for the current group.
        if current_req is not None and direction == "ingress":
            is_sse = any(
                kw in body
                for kw in ("message_start", "content_block_start",
                            "content_block_delta", "content_block_stop",
                            "message_delta", "message_stop")
            )
            # Accept events with matching URL or no URL (H2 mid-join).
            if is_sse and (not url or "completion" in url):
                current_events.append(ev)

    if current_req is not None:
        groups.append((current_req, current_events))

    return groups


def deduplicate(events):
    """Remove duplicate events (same body_snippet within a sliding window).

    NSS read+return probes both fire for the same SSL_read, producing
    two copies of every SSE chunk. The duplicates are interleaved with
    other event types, so simple consecutive dedup is insufficient.
    We use a sliding window of recent body_snippets to catch them.
    """
    deduped = []
    recent = set()
    window = []
    window_size = 8

    for ev in events:
        body = ev.get("body_snippet", "")
        if body in recent:
            continue
        deduped.append(ev)
        recent.add(body)
        window.append(body)
        if len(window) > window_size:
            old = window.pop(0)
            recent.discard(old)
    return deduped


def reconstruct_response(events):
    """Extract the full text response from SSE content_block_delta events."""
    text = ""
    for ev in events:
        body = ev.get("body_snippet", "")
        if "content_block_delta" not in body or "text_delta" not in body:
            continue
        for part in body.split("\n"):
            part = part.strip()
            if part.startswith("data: "):
                try:
                    data = json.loads(part[6:])
                    text += data["delta"]["text"]
                except (json.JSONDecodeError, KeyError):
                    pass
    return text


def get_request_info(req_event):
    """Extract request metadata from the egress event."""
    method = req_event.get("http_method", "?")
    url = req_event.get("url", "?")
    pid = req_event.get("pid", 0)
    proc = req_event.get("process_name", "")
    body = req_event.get("body_snippet", "") or req_event.get("request_body", "")

    # Browser API uses {"prompt": "..."} format (not messages array).
    prompt = ""
    if body:
        try:
            data = json.loads(body)
            prompt = data.get("prompt", "")[:200]
        except (json.JSONDecodeError, KeyError):
            pass

    return method, url, pid, proc, prompt


def print_raw(events):
    """Print all events with details."""
    for i, ev in enumerate(events):
        direction = ev.get("direction", "")
        method = ev.get("http_method", "")
        status = ev.get("status_code", 0)
        url = ev.get("url", "")
        body = ev.get("body_snippet", "")
        snippet = body[:200] if body else ""
        url_tag = f" url={url[:60]}" if url else ""
        print(f"  [{i+1}] {direction:8s} {method:6s} status={status} bodyLen={len(body)}{url_tag}")
        if snippet:
            print(f"      {snippet!r}")


def main():
    parser = argparse.ArgumentParser(
        description="Read browser (claude.ai) responses from traffic-agent events"
    )
    parser.add_argument("-f", "--file", default="events.json", help="Path to events.json")
    parser.add_argument("--all", action="store_true", help="Show all responses, not just the last")
    parser.add_argument("--raw", action="store_true", help="Show raw event details (before dedup)")
    args = parser.parse_args()

    try:
        events = load_events(args.file)
    except FileNotFoundError:
        print(f"Error: {args.file} not found", file=sys.stderr)
        sys.exit(1)

    groups = find_completion_groups(events)

    if not groups:
        print("No browser completion (POST /completion) groups found.")
        sys.exit(0)

    # Filter out empty groups (preflight/navigation requests with no SSE response).
    groups = [(req, resp) for req, resp in groups if resp]
    if not groups:
        print("No browser completion responses with SSE data found.")
        sys.exit(0)

    targets = groups if args.all else [groups[-1]]

    for i, (req, resp_events) in enumerate(targets):
        method, url, pid, proc, prompt = get_request_info(req)
        n_raw = len(resp_events)
        deduped = deduplicate(resp_events)
        n_deduped = len(deduped)
        n_deltas = sum(
            1 for ev in deduped
            if "content_block_delta" in ev.get("body_snippet", "")
        )

        if len(targets) > 1:
            print(f"{'=' * 60}")
        print(f"Request: {method} {url}")
        print(f"Process: {proc} (pid={pid})")
        if prompt:
            print(f"Prompt:  {prompt}")
        print(f"Events:  {n_raw} raw, {n_deduped} after dedup, {n_deltas} content tokens")
        print(f"{'-' * 60}")

        if args.raw:
            print_raw(resp_events)
            print(f"{'-' * 60}")

        text = reconstruct_response(deduped)
        if text:
            print(f"Response:\n{text}")
        else:
            print("(no SSE content_block_delta tokens found)")
        print()


if __name__ == "__main__":
    main()
