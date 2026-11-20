# OSV integration: free public data, local-first analysis

## Architecture

The host-side opt-in `collector/osv_fetch.py` submits versioned Package URLs (PURLs) from a normalized SBOM inventory to the public OSV `POST https://api.osv.dev/v1/querybatch` endpoint. The response is saved as a local JSON cache with a retrieval timestamp. `scanner/osv_analyze.py` runs **offline** against that cache and labels results as `potentially_affected`, never confirmed vulnerable.

The API is public and does not require a paid subscription for this PoC. Availability, usage limits and terms can change: verify official OSV documentation before relying on it operationally. Queries disclose package names and versions to OSV; explicit operator opt-in is required.

## Commands

```sh
cd poc/vire
python3 scanner/sbom.py fixtures/sample.cdx.json > reports/sbom-inventory.json
python3 collector/osv_fetch.py --sbom reports/sbom-inventory.json --output reports/osv-cache.json
python3 scanner/osv_analyze.py --cache reports/osv-cache.json --max-age-hours 168
```

The bundled SBOM is synthetic and may have no valid PURLs; an empty batch intentionally makes no network request. Supply a real normalized SBOM inventory to query real packages.

## Safety, cost and limitations

- No paid API, API key, account or mandatory cloud service.
- At most 100 distinct versioned PURLs per batch; 30-second HTTP timeout; 5 MiB response cap; 20 MiB local input cap.
- Cache output permissions are `0600`; do not commit it to Git.
- No scheduled polling, automatic retries, uncontrolled concurrency or continuous external dependency.
- Cache freshness is explicitly reported (default 168 hours). Stale cache can still be inspected but must not be represented as current.
- OSV query results are candidates. Linux distribution backports, distro package epochs/revisions, and vendor advisory decisions must be checked before claiming applicability.
- Results may be incomplete due to ecosystem coverage or query semantics. No finding does not prove safety.
- The cache is not authenticated or signed; a future pipeline must record provenance and integrity before treating external evidence as authoritative.
- No automatic remediation or enforcement.

## Provider assessment (initial, requires periodic review)

| Field | Value |
| --- | --- |
| Provider | Open Source Vulnerabilities (OSV) |
| Endpoint | https://api.osv.dev/v1/querybatch |
| Access | Public endpoint; no paid account required in this implementation |
| Credentials | None |
| License / redistribution | Review current OSV dataset and individual advisory terms before redistribution |
| Quotas | Not assumed unlimited; throttle manually, cap requests and prefer bulk sync for scale |
| Fallback | Existing local cache, with age clearly displayed |
| Privacy | Package URLs and versions leave the operator's environment when fetching |
| Verified | Integration designed 2026-11-20; live API behavior not yet validated |
