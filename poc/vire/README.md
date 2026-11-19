# VIRE Docker PoC 001

An **offline, read-only proof of concept** for vulnerability applicability decisions. This is not yet a live CVE scanner.

## Run

```sh
cd poc/vire
mkdir -p reports
chmod 777 reports # demo only: allows the unprivileged container to write
docker compose up --build --abort-on-container-exit
cat reports/report.json
docker compose down
```

To run tests without Docker:

```sh
cd poc/vire/scanner
python3 -m unittest -v
```

## What this proves

- A non-root, network-isolated scanner can evaluate inventory and advisory data.
- The report contains explicit affected / not_affected / needs_verification statuses and evidence.
- An NGINX demo container runs without published ports, but the scanner **does not inspect it**.
- All advisories are **synthetic DEMO identifiers**, not real CVEs or claims about nginx vulnerabilities.

## Next milestones

1. Collect a genuine nginx package inventory safely via an explicit read-only collector.
2. Implement vendor advisory, NVD, OSV and CISA KEV adapters with provenance and caching.
3. Implement distro package and backport-aware applicability; avoid relying on upstream version alone.
4. Add a deterministic remediation planner that never executes changes.
5. Replace the demo output directory permissions with an explicit matching host/container UID strategy.

Do not use the synthetic report for production vulnerability decisions.
