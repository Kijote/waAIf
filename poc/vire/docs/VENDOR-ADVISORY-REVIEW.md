# Distribution vendor advisory review (offline prototype)

This module conservatively correlates OSV candidates with **normalized** distribution vendor evidence for Debian, Ubuntu and Alpine. It does **not** download or parse the distributions' official feeds yet. The source JSON must be obtained from a trusted normalization pipeline.

## Input contracts

- OSV candidates: output of `scanner/osv_analyze.py`.
- Package inventory: `{"packages":[{"purl":"...","version":"...","distro":"debian|ubuntu|alpine","distro_release":"...","source_package":"...","installed_version":"..."}]}`.
- Vendor advisories: `{"source":"normalized_vendor_advisories","entries":[{"distro":"...","distro_release":"...","source_package":"...","installed_version":"...","vulnerability_id":"CVE-...","state":"fixed|affected|not_affected|unknown","advisory_url":"https://..."}]}`.

The evidence must match **exactly** the distribution, release, source package, installed package version and vulnerability identifier. Multiple matches, missing evidence or incomplete provenance produce `needs_verification`. The module does not implement dpkg/apk version ordering or assume that an upstream version is decisive.

## Run offline

```sh
python3 scanner/vendor_review.py \
  --osv reports/osv-candidates.json \
  --inventory reports/distro-packages.json \
  --advisories reports/vendor-advisories.json
```

## Interpretation

`vendor_fixed` / `vendor_not_affected` / `vendor_affected` indicate **reported vendor evidence**, not independent validation of the source feed. These statuses are **not safe for enforcement** until the normalization pipeline verifies advisory authenticity, update freshness, and the correct distro package revision. `needs_verification` means insufficient evidence.

## Free community path and next steps

Prefer public, no-cost vendor sources: Debian Security Tracker, Ubuntu Security Notices / Ubuntu CVE Tracker and Alpine SecDB. Before enabling connectors, document official feed URLs, current licenses, redistribution rights, free access, quotas, caching and privacy. Build separate parsers for their actual schemas, validate source provenance, and use distro-native version comparison (dpkg / apk) where appropriate.

No mandatory SaaS, paid API, LLM or waAIf Cloud dependency.
