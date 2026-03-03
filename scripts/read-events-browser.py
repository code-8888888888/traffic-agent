#!/usr/bin/env python3
"""Read captured browser (claude.ai) request and response from traffic-agent output.

Reconstructs full conversation turns from the NDJSON event stream:
  - REQUEST:  POST /completion egress event with prompt text
  - RESPONSE: Ingress SSE content_block_delta events (may have empty URL due
              to H2 mid-connection join — grouped by proximity to the request)

Handles NSS read+return probe deduplication (sliding window).

Usage:
    ./scripts/read-events-browser.py                          # last turn
    ./scripts/read-events-browser.py --all                    # all turns
    ./scripts/read-events-browser.py --raw                    # show raw events
    ./scripts/read-events-browser.py --request                # show request body
    ./scripts/read-events-browser.py --headers                # show request headers
    ./scripts/read-events-browser.py -f /path/to/stdout.jsonl # custom file
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
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return events


def find_completion_groups(events):
    """Find browser completion request/response groups.

    Groups are formed around POST /completion egress events. H2 splits the
    request into two egress events (headers-only + body), so we merge
    consecutive egress events for the same URL. SSE response chunks arrive
    as ingress events — they may have the /completion URL or an empty URL
    (H2 mid-connection join).
    """
    groups = []
    current_req = None
    current_events = []

    for ev in events:
        url = ev.get("url", "")
        direction = ev.get("direction", "")
        body = ev.get("body_snippet", "")
        method = ev.get("http_method", "")

        # Completion POST request (may arrive as 2 events: headers + body).
        if direction == "egress" and "completion" in url and method == "POST":
            req_body = ev.get("request_body", "") or body
            has_body = bool(req_body and "prompt" in req_body)

            if current_req is not None and not current_events and has_body:
                # Body event right after header event — merge into current.
                current_req["_merged_body"] = (
                    ev.get("request_body", "") or ev.get("body_snippet", "")
                )
                continue

            # New request group.
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
            if is_sse and (not url or "completion" in url):
                current_events.append(ev)

    if current_req is not None:
        groups.append((current_req, current_events))

    return groups


def deduplicate(events):
    """Remove duplicate events (NSS read+return probes fire twice)."""
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
                    delta = data.get("delta", {})
                    text += delta.get("text", "")
                except (json.JSONDecodeError, KeyError):
                    pass
    return text


def extract_prompt(req_event):
    """Extract the user's prompt from the request body."""
    body = (
        req_event.get("_merged_body", "")
        or req_event.get("request_body", "")
        or req_event.get("body_snippet", "")
    )
    if not body:
        return ""
    try:
        data = json.loads(body)
        return data.get("prompt", "")
    except (json.JSONDecodeError, KeyError):
        return ""


def extract_model(req_event):
    """Extract the model name from the request body."""
    body = (
        req_event.get("_merged_body", "")
        or req_event.get("request_body", "")
        or req_event.get("body_snippet", "")
    )
    if not body:
        return ""
    try:
        data = json.loads(body)
        return data.get("model", "")
    except (json.JSONDecodeError, KeyError):
        return ""


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
    p = argparse.ArgumentParser(
        description="Read browser (claude.ai) request and response from traffic-agent events"
    )
    p.add_argument("-f", "--file", default="stdout.jsonl",
                   help="Path to NDJSON events file (default: stdout.jsonl)")
    p.add_argument("--all", action="store_true",
                   help="Show all turns, not just the last")
    p.add_argument("--raw", action="store_true",
                   help="Show raw event details")
    p.add_argument("--request", action="store_true",
                   help="Show the full request body (JSON)")
    p.add_argument("--headers", action="store_true",
                   help="Show request headers")
    args = p.parse_args()

    try:
        events = load_events(args.file)
    except FileNotFoundError:
        print(f"Error: {args.file} not found", file=sys.stderr)
        sys.exit(1)

    groups = find_completion_groups(events)

    # Filter out empty groups.
    groups = [(req, resp) for req, resp in groups if resp]
    if not groups:
        print("No browser completion responses found.")
        print(f"  (searched {len(events)} events in {args.file})")
        sys.exit(0)

    targets = groups if args.all else [groups[-1]]

    for idx, (req, resp_events) in enumerate(targets):
        url = req.get("url", "?")
        pid = req.get("pid", 0)
        proc = req.get("process_name", "")
        ts = req.get("timestamp", "")
        prompt = extract_prompt(req)
        model = extract_model(req)

        deduped = deduplicate(resp_events)
        n_deltas = sum(
            1 for ev in deduped
            if "content_block_delta" in ev.get("body_snippet", "")
        )

        if len(targets) > 1:
            print(f"\n{'=' * 70}")
            print(f"  Turn {idx + 1}/{len(targets)}")
            print(f"{'=' * 70}")

        # Request info.
        print(f"\n--- REQUEST ---")
        print(f"Time:    {ts}")
        print(f"URL:     POST {url}")
        print(f"Process: {proc} (pid={pid})")
        if model:
            print(f"Model:   {model}")
        if prompt:
            print(f"Prompt:  {prompt}")

        if args.headers:
            headers = req.get("request_headers", {})
            if headers:
                print(f"\nHeaders:")
                for k, v in sorted(headers.items()):
                    # Truncate long values.
                    v_display = v if len(v) <= 100 else v[:100] + "..."
                    print(f"  {k}: {v_display}")

        if args.request:
            body = (
                req.get("_merged_body", "")
                or req.get("request_body", "")
                or req.get("body_snippet", "")
            )
            if body:
                try:
                    formatted = json.dumps(json.loads(body), indent=2, ensure_ascii=False)
                    print(f"\nRequest Body:\n{formatted}")
                except json.JSONDecodeError:
                    print(f"\nRequest Body (raw):\n{body}")

        # Response info.
        print(f"\n--- RESPONSE ---")
        print(f"Events:  {len(resp_events)} raw, {len(deduped)} deduped, {n_deltas} content chunks")

        if args.raw:
            print_raw(resp_events)

        text = reconstruct_response(deduped)
        if text:
            print(f"\n{text}")
        else:
            print("(no response text found)")

        print()


if __name__ == "__main__":
    main()
