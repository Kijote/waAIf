#!/usr/bin/env python3
"""Replay deterministic, local-only HTTP requests and emit a ground-truth manifest."""
import argparse
import json
import time
from urllib.parse import urlparse
from urllib.request import urlopen
from urllib.error import HTTPError

SCENARIOS = {
    "legitimate": ["/", "/health", "/api/items", "/"],
    "reconnaissance": ["/admin", "/.git/config", "/wp-admin", "/does-not-exist"],
}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8088")
    parser.add_argument("--scenario", choices=SCENARIOS, default="legitimate")
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--output", default="ground-truth.jsonl")
    args = parser.parse_args()
    url = urlparse(args.base_url)
    if url.hostname not in ("127.0.0.1", "localhost", "::1") or url.scheme != "http":
        parser.error("Only local HTTP targets are permitted")
    if args.repeats < 1 or args.repeats > 10000:
        parser.error("repeats must be between 1 and 10000")
    with open(args.output, "w", encoding="utf-8") as out:
        for repeat in range(args.repeats):
            for index, path in enumerate(SCENARIOS[args.scenario]):
                event = {
                    "scenario": args.scenario,
                    "campaign_id": f"{args.scenario}-{repeat}",
                    "request_index": index,
                    "path": path,
                    "label": "legitimate" if args.scenario == "legitimate" else "malicious",
                    "sent_at_unix_ns": time.time_ns(),
                }
                try:
                    with urlopen(args.base_url + path, timeout=5) as response:
                        event["http_status"] = response.status
                except HTTPError as error:
                    event["http_status"] = error.code
                out.write(json.dumps(event) + "\n")
    print(f"Wrote {args.output}")

if __name__ == "__main__":
    main()
