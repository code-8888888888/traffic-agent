#!/usr/bin/env python3
"""Reconstruct captured HTTP responses from traffic-agent events.json.

Reads NDJSON events produced by traffic-agent and reconstructs full
responses by extracting SSE content_block_delta tokens. Supports
filtering by URL pattern and showing raw event details.

Usage:
    ./scripts/read-events.py                          # last response
    ./scripts/read-events.py --all                    # all responses
    ./scripts/read-events.py --url /v1/messages       # filter by URL
    ./scripts/read-events.py --raw                    # show all event details
    ./scripts/read-events.py -f /path/to/events.json  # custom file
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


def find_request_groups(events, url_filter=None):
    """Split events into groups, each starting with an egress request."""
    groups = []
    current = []
    for ev in events:
        url = ev.get("url", "")
        if url_filter and url_filter not in url:
            continue
        if ev.get("direction") == "egress" and ev.get("http_method"):
            if current:
                groups.append(current)
            current = [ev]
        elif current:
            current.append(ev)
    if current:
        groups.append(current)
    return groups


def reconstruct_response(group):
    """Extract the full text response from SSE content_block_delta events."""
    text = ""
    for ev in group:
        body = ev.get("body_snippet", "")
        if "content_block_delta" not in body or "text_delta" not in body:
            continue
        for part in body.split("\n"):
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
    body = req.get("body_snippet", "") or req.get("request_body", "")

    # Try to extract the user prompt from the request body JSON.
    prompt = ""
    if body:
        try:
            data = json.loads(body)
            messages = data.get("messages", [])
            if messages:
                last = messages[-1]
                content = last.get("content", "")
                if isinstance(content, list):
                    for c in content:
                        if c.get("type") == "text":
                            prompt = c["text"][:200]
                            break
                elif isinstance(content, str):
                    prompt = content[:200]
        except (json.JSONDecodeError, KeyError):
            pass

    return method, url, pid, proc, prompt


def print_raw(group):
    """Print all events in a group with details."""
    for i, ev in enumerate(group):
        direction = ev.get("direction", "")
        method = ev.get("http_method", "")
        status = ev.get("status_code", 0)
        url = ev.get("url", "")
        body = ev.get("body_snippet", "")
        snippet = body[:200] if body else ""
        print(f"  [{i+1}] {direction:8s} {method:6s} status={status} bodyLen={len(body)}")
        if snippet:
            print(f"      {snippet!r}")


def main():
    parser = argparse.ArgumentParser(description="Read traffic-agent captured events")
    parser.add_argument("-f", "--file", default="events.json", help="Path to events.json")
    parser.add_argument("--url", default="/v1/messages", help="URL filter (default: /v1/messages)")
    parser.add_argument("--all", action="store_true", help="Show all responses, not just the last")
    parser.add_argument("--raw", action="store_true", help="Show raw event details")
    parser.add_argument("--no-filter", action="store_true", help="Don't filter by URL")
    args = parser.parse_args()

    try:
        events = load_events(args.file)
    except FileNotFoundError:
        print(f"Error: {args.file} not found", file=sys.stderr)
        sys.exit(1)

    url_filter = None if args.no_filter else args.url
    groups = find_request_groups(events, url_filter)

    if not groups:
        print("No matching request/response groups found.")
        sys.exit(0)

    targets = groups if args.all else [groups[-1]]

    for i, group in enumerate(targets):
        method, url, pid, proc, prompt = get_request_info(group)
        n_events = len(group)
        n_deltas = sum(
            1 for ev in group
            if "content_block_delta" in ev.get("body_snippet", "")
        )

        if len(targets) > 1:
            print(f"{'=' * 60}")
        print(f"Request: {method} {url}")
        print(f"Process: {proc} (pid={pid})")
        if prompt:
            print(f"Prompt:  {prompt}")
        print(f"Events:  {n_events} total, {n_deltas} content tokens")
        print(f"{'-' * 60}")

        if args.raw:
            print_raw(group)
            print(f"{'-' * 60}")

        text = reconstruct_response(group)
        if text:
            print(f"Response:\n{text}")
        else:
            print("(no SSE content_block_delta tokens found)")
        print()


if __name__ == "__main__":
    main()
