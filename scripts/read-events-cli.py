#!/usr/bin/env python3
"""Read captured Claude CLI (Claude Code) request and response from traffic-agent output.

Reconstructs full API turns from the NDJSON event stream:
  - REQUEST:  POST /v1/messages egress event with messages array
  - RESPONSE: Ingress SSE content_block_delta events (gzip-compressed,
              decompressed by traffic-agent)

Claude CLI uses the Anthropic API directly via HTTP/1.1 over TLS.

Usage:
    ./scripts/read-events-cli.py                          # last turn
    ./scripts/read-events-cli.py --all                    # all turns
    ./scripts/read-events-cli.py --raw                    # show raw events
    ./scripts/read-events-cli.py --request                # show request body
    ./scripts/read-events-cli.py --headers                # show request headers
    ./scripts/read-events-cli.py --tools                  # show tool use events
    ./scripts/read-events-cli.py -f /path/to/stdout.jsonl # custom file
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


def find_request_groups(events):
    """Split events into request/response groups for /v1/messages."""
    groups = []
    current_req = None
    current_body_ev = None
    current_events = []

    for ev in events:
        url = ev.get("url", "")
        direction = ev.get("direction", "")
        method = ev.get("http_method", "")

        # /v1/messages POST request.
        if direction == "egress" and "/v1/messages" in url and method == "POST":
            req_body = ev.get("request_body", "") or ev.get("body_snippet", "")
            if req_body and "messages" in req_body:
                if current_req is not None:
                    if current_body_ev:
                        current_req["_merged_body"] = (
                            current_body_ev.get("request_body", "")
                            or current_body_ev.get("body_snippet", "")
                        )
                    groups.append((current_req, current_events))
                current_body_ev = ev
                if current_req is None or current_events:
                    current_req = ev
                    current_events = []
                continue
            else:
                if current_req is not None:
                    if current_body_ev:
                        current_req["_merged_body"] = (
                            current_body_ev.get("request_body", "")
                            or current_body_ev.get("body_snippet", "")
                        )
                    groups.append((current_req, current_events))
                current_req = ev
                current_body_ev = None
                current_events = []
                continue

        # Collect ingress response events.
        if current_req is not None and direction == "ingress":
            body = ev.get("body_snippet", "")
            # Accept events with /v1/messages URL or no URL but containing SSE data.
            has_sse = any(kw in body for kw in (
                "message_start", "content_block_start",
                "content_block_delta", "content_block_stop",
                "message_delta", "message_stop",
            ))
            if has_sse and (not url or "/v1/messages" in url):
                current_events.append(ev)

    if current_req is not None:
        if current_body_ev:
            current_req["_merged_body"] = (
                current_body_ev.get("request_body", "")
                or current_body_ev.get("body_snippet", "")
            )
        groups.append((current_req, current_events))

    return groups


def reconstruct_response(events, include_tools=False):
    """Extract the full text response and optionally tool use from SSE events."""
    text = ""
    tool_uses = []
    current_tool = None

    for ev in events:
        body = ev.get("body_snippet", "")
        for part in body.split("\n"):
            part = part.strip()
            if not part.startswith("data: "):
                continue
            try:
                data = json.loads(part[6:])
            except json.JSONDecodeError:
                continue

            event_type = data.get("type", "")

            if event_type == "content_block_start":
                cb = data.get("content_block", {})
                if cb.get("type") == "tool_use":
                    current_tool = {
                        "name": cb.get("name", ""),
                        "id": cb.get("id", ""),
                        "input_json": "",
                    }

            elif event_type == "content_block_delta":
                delta = data.get("delta", {})
                if delta.get("type") == "text_delta":
                    text += delta.get("text", "")
                elif delta.get("type") == "input_json_delta":
                    if current_tool:
                        current_tool["input_json"] += delta.get("partial_json", "")

            elif event_type == "content_block_stop":
                if current_tool:
                    tool_uses.append(current_tool)
                    current_tool = None

    if include_tools:
        return text, tool_uses
    return text


def extract_prompt(req_event):
    """Extract the user's prompt from the messages array."""
    body = (
        req_event.get("_merged_body", "")
        or req_event.get("request_body", "")
        or req_event.get("body_snippet", "")
    )
    if not body:
        return ""
    try:
        data = json.loads(body)
        messages = data.get("messages", [])
        if not messages:
            return ""
        # Find the last user message.
        for msg in reversed(messages):
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, list):
                    for c in content:
                        if c.get("type") == "text":
                            return c["text"]
                elif isinstance(content, str):
                    return content
        return ""
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
        description="Read Claude CLI request and response from traffic-agent events"
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
    p.add_argument("--tools", action="store_true",
                   help="Show tool use events (tool name + input)")
    args = p.parse_args()

    try:
        events = load_events(args.file)
    except FileNotFoundError:
        print(f"Error: {args.file} not found", file=sys.stderr)
        sys.exit(1)

    groups = find_request_groups(events)

    # Filter out groups with no response events.
    groups = [(req, resp) for req, resp in groups if resp]
    if not groups:
        # Also show groups without responses for --request mode.
        if args.request:
            groups = find_request_groups(events)
        if not groups:
            print("No Claude CLI (/v1/messages) request/response groups found.")
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

        n_deltas = sum(
            1 for ev in resp_events
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
            # Truncate very long prompts.
            display = prompt if len(prompt) <= 500 else prompt[:500] + "..."
            print(f"Prompt:  {display}")

        if args.headers:
            headers = req.get("request_headers", {})
            if headers:
                print(f"\nHeaders:")
                for k, v in sorted(headers.items()):
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
        print(f"Events:  {len(resp_events)} total, {n_deltas} content chunks")

        if args.raw:
            print_raw(resp_events)

        text, tool_uses = reconstruct_response(resp_events, include_tools=True)

        if args.tools and tool_uses:
            print(f"\nTool Uses ({len(tool_uses)}):")
            for tu in tool_uses:
                print(f"  - {tu['name']}")
                if tu["input_json"]:
                    try:
                        inp = json.loads(tu["input_json"])
                        formatted = json.dumps(inp, indent=4, ensure_ascii=False)
                        for line in formatted.split("\n"):
                            print(f"    {line}")
                    except json.JSONDecodeError:
                        print(f"    {tu['input_json'][:200]}")

        if text:
            print(f"\n{text}")
        elif not tool_uses:
            print("(no response text found)")

        print()


if __name__ == "__main__":
    main()
