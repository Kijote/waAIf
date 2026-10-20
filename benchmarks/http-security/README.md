# HTTP Security Benchmark Lab

**Status:** Minimal lab scaffold, not a completed benchmark. See [BENCH-001](../../docs/research/BENCH-001.md).

## Requirements

Docker Compose and Python 3.10+ on the host.

## Start the local lab

```sh
cd benchmarks/http-security
docker compose up -d
curl http://127.0.0.1:8088/health
python3 scripts/replay.py --scenario legitimate --repeats 10 --output /tmp/waaif-legitimate.jsonl
python3 scripts/replay.py --scenario reconnaissance --repeats 10 --output /tmp/waaif-reconnaissance.jsonl
docker compose logs nginx
docker compose down
```

nginx writes structured JSONL access logs into a Docker volume. The replay tool is restricted to loopback HTTP targets and emits scenario-level ground-truth labels.

## Important limitations

- No CrowdSec or waAIf detector is connected yet.
- Ground truth is at request level and **does not yet correlate to nginx request IDs**; do not use this scaffold to claim precision/recall.
- Traffic is sequential and does not represent realistic throughput or distributed source identities.
- This configuration is **not production hardened**; it exposes only loopback port 8088.
- The nginx container uses an explicitly pinned major/minor tag but not an immutable image digest; production-quality reproducibility requires digest pinning.
- Do not publish benchmarks or superiority claims before the full protocol is implemented and run.
