#!/usr/bin/env python3
"""Read captured HTTP request and response from traffic-agent output.

Generic event reader with URL filtering. For source-specific scripts:
    ./scripts/read-events-cli.py       # Claude CLI (/v1/messages)
    ./scripts/read-events-browser.py   # Browser / claude.ai (/completion)

Usage:
    ./scripts/read-events.py                          # last response
    ./scripts/read-events.py --all                    # all responses
    ./scripts/read-events.py --url /api/              # filter by URL
    ./scripts/read-events.py --raw                    # show all event details
    ./scripts/read-events.py --request                # show request body
    ./scripts/read-events.py --headers                # show request/response headers
    ./scripts/read-events.py --no-filter              # show all events (no URL filter)
    ./scripts/read-events.py -f /path/to/stdout.jsonl # custom file
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


def find_request_groups(events, url_filter=None):
    """Split events into groups, each starting with an egress request.

    H2 splits requests into two egress events (headers + body). When two
    consecutive egress events share the same URL and no ingress events
    have arrived between them, the second is merged into the first.
    """
    groups = []
    current = []
    for ev in events:
        url = ev.get("url", "")
        direction = ev.get("direction", "")
        method = ev.get("http_method", "")

        if url_filter and url_filter not in url:
            # Still collect URL-less ingress events for the current group.
            if current and direction == "ingress" and not url:
                current.append(ev)
            continue

        if direction == "egress" and method:
            # Merge body event into preceding header-only event for same URL.
            if (current and len(current) == 1
                    and current[0].get("direction") == "egress"
                    and current[0].get("url") == url):
                req_body = ev.get("request_body", "") or ev.get("body_snippet", "")
                if req_body:
                    current[0]["_merged_body"] = req_body
                continue
            if current:
                groups.append(current)
            current = [ev]
        elif current:
            current.append(ev)
    if current:
        groups.append(current)
    return groups


def reconstruct_response(group):
    """Extract text response from SSE content_block_delta events."""
    text = ""
    for ev in group:
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


def get_request_info(group):
    """Extract request metadata from the egress event."""
    req = group[0]
    method = req.get("http_method", "?")
    url = req.get("url", "?")
    pid = req.get("pid", 0)
    proc = req.get("process_name", "")
    ts = req.get("timestamp", "")
    status = 0
    body = (req.get("_merged_body", "")
            or req.get("request_body", "")
            or req.get("body_snippet", ""))

    # Find status code from response events.
    for ev in group[1:]:
        sc = ev.get("status_code", 0)
        if sc:
            status = sc
            break

    # Try to extract the user prompt.
    prompt = ""
    if body:
        try:
            data = json.loads(body)
            # Browser format.
            prompt = data.get("prompt", "")
            # CLI format.
            if not prompt:
                messages = data.get("messages", [])
                for msg in reversed(messages):
                    if msg.get("role") == "user":
                        content = msg.get("content", "")
                        if isinstance(content, list):
                            for c in content:
                                if c.get("type") == "text":
                                    prompt = c["text"]
                                    break
                        elif isinstance(content, str):
                            prompt = content
                        break
        except (json.JSONDecodeError, KeyError):
            pass

    return method, url, pid, proc, ts, status, prompt, body


def print_raw(group):
    """Print all events in a group with details."""
    for i, ev in enumerate(group):
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
        description="Read traffic-agent captured request and response events"
    )
    p.add_argument("-f", "--file", default="stdout.jsonl",
                   help="Path to NDJSON events file (default: stdout.jsonl)")
    p.add_argument("--url", default=None,
                   help="URL filter substring (e.g. /v1/messages, /completion)")
    p.add_argument("--all", action="store_true",
                   help="Show all request/response groups, not just the last")
    p.add_argument("--raw", action="store_true",
                   help="Show raw event details")
    p.add_argument("--request", action="store_true",
                   help="Show full request body")
    p.add_argument("--headers", action="store_true",
                   help="Show request headers")
    p.add_argument("--no-filter", action="store_true",
                   help="Don't filter by URL")
    args = p.parse_args()

    try:
        events = load_events(args.file)
    except FileNotFoundError:
        print(f"Error: {args.file} not found", file=sys.stderr)
        sys.exit(1)

    url_filter = None if args.no_filter else args.url
    groups = find_request_groups(events, url_filter)

    if not groups:
        print("No matching request/response groups found.")
        print(f"  (searched {len(events)} events in {args.file})")
        if url_filter:
            print(f"  (URL filter: {url_filter})")
        sys.exit(0)

    targets = groups if args.all else [groups[-1]]

    for idx, group in enumerate(targets):
        method, url, pid, proc, ts, status, prompt, req_body = get_request_info(group)
        n_events = len(group)
        n_responses = sum(1 for ev in group if ev.get("direction") == "ingress")
        n_deltas = sum(
            1 for ev in group
            if "content_block_delta" in ev.get("body_snippet", "")
        )

        if len(targets) > 1:
            print(f"\n{'=' * 70}")
            print(f"  Group {idx + 1}/{len(targets)}")
            print(f"{'=' * 70}")

        # Request info.
        print(f"\n--- REQUEST ---")
        print(f"Time:    {ts}")
        print(f"URL:     {method} {url}")
        print(f"Process: {proc} (pid={pid})")
        if status:
            print(f"Status:  {status}")
        if prompt:
            display = prompt if len(prompt) <= 500 else prompt[:500] + "..."
            print(f"Prompt:  {display}")
        print(f"Events:  {n_events} total ({n_responses} responses, {n_deltas} content chunks)")

        if args.headers:
            headers = group[0].get("request_headers", {})
            if headers:
                print(f"\nRequest Headers:")
                for k, v in sorted(headers.items()):
                    v_display = v if len(v) <= 100 else v[:100] + "..."
                    print(f"  {k}: {v_display}")

        if args.request and req_body:
            try:
                formatted = json.dumps(json.loads(req_body), indent=2, ensure_ascii=False)
                print(f"\nRequest Body:\n{formatted}")
            except json.JSONDecodeError:
                print(f"\nRequest Body (raw):\n{req_body[:2000]}")

        if args.raw:
            print(f"\n--- RAW EVENTS ---")
            print_raw(group)

        # Response.
        print(f"\n--- RESPONSE ---")

        # Show response headers from the first ingress event.
        if args.headers:
            for ev in group:
                if ev.get("direction") == "ingress":
                    resp_headers = ev.get("response_headers", {})
                    if resp_headers:
                        print(f"Response Headers:")
                        for k, v in sorted(resp_headers.items()):
                            v_display = v if len(v) <= 100 else v[:100] + "..."
                            print(f"  {k}: {v_display}")
                    break

        text = reconstruct_response(group)
        if text:
            print(f"\n{text}")
        else:
            # Show body snippets from response events.
            bodies = []
            for ev in group[1:]:
                if ev.get("direction") == "ingress":
                    b = ev.get("body_snippet", "")
                    if b:
                        bodies.append(b)
            if bodies:
                combined = "\n".join(bodies[:5])
                if len(bodies) > 5:
                    combined += f"\n... ({len(bodies) - 5} more events)"
                print(f"\nBody:\n{combined}")
            else:
                print("(no response body found)")

        print()


if __name__ == "__main__":
    main()
