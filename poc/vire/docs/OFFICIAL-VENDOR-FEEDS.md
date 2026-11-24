# Official distro security feed snapshots (community / no paid API)

The opt-in host-side downloader `collector/vendor_feed_fetch.py` currently supports **Debian Security Tracker** and **Alpine SecDB** official public HTTPS endpoints. Ubuntu's public security information is relevant, but its machine-readable endpoint and schema have **not yet been verified**, so the connector intentionally rejects Ubuntu instead of guessing.

## Run

```sh
cd poc/vire
python3 collector/vendor_feed_fetch.py --distro debian --output reports/debian-tracker.json
python3 collector/vendor_feed_fetch.py --distro alpine --release v3.22 --repository main --output reports/alpine-v3.22-main.json
python3 collector/vendor_feed_fetch.py --distro alpine --release v3.22 --repository community --output reports/alpine-v3.22-community.json
```

Each output is a raw snapshot with a separate `.metadata.json` containing official source URL, retrieval time, SHA-256, byte length, and `verified_vendor_status:false`. A SHA-256 checksum detects later file changes but does not prove publisher authenticity beyond the host's TLS trust chain.

**No normalization or installed-version comparison occurs here.** Do not feed these raw snapshots directly into `vendor_review.py`, which expects normalized evidence. A future adapter must parse the official schema, handle distro-native version comparison, and bind advisories to installed package revisions.

## Operational boundaries

- Public HTTPS, no paid API, subscription, API key, or waAIf Cloud account required.
- Explicit operator opt-in; no scheduled polling or unbounded concurrency.
- 60-second request timeout, 120 MiB response limit, private local file permissions, fixed provider URLs.
- A Debian snapshot may be large. Downloads are whole-file and in memory in this initial prototype; add streaming and conditional HTTP caching before large-scale deployment.
- No automated remediation, no automatic claims of fixed/affected, and no silent fallback to stale data.
- Review provider-specific licensing and redistribution rights before republishing vendor data. Publicly accessible is not necessarily redistributable.

## Official source references

- Debian Security Tracker: https://security-tracker.debian.org/tracker/data/json
- Alpine SecDB: https://secdb.alpinelinux.org/ (release-specific `main.json` and `community.json`)
- Ubuntu security CVEs: https://ubuntu.com/security/cves/about (documentation only; connector pending)

This implementation is deliberately free-first and offline-compatible after snapshot acquisition.
