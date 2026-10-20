# Threat Intelligence Licensing and Distribution Boundaries

**Reviewed:** 2026-10-20  
**Scope:** CrowdSec and Wordfence; initial source-based technical assessment, not legal advice.

## CrowdSec

- The CrowdSec engine repository identifies an MIT license; its project README also states that detection rules on the Hub are MIT-licensed.
- The community blocklist is a **service/data product**, not simply the engine's MIT-licensed source code. Access and coverage vary by contribution and subscription.
- The CrowdSec Console pricing comparison marks **third-party service use rights** as **not authorized** for Community and authorized for Premium and Advanced, subject to applicable terms and plan limits.
- **Decision:** waAIf may study compatible open detection logic and benchmark against CrowdSec, preserving required attribution. Do not import or redistribute CrowdSec community/premium blocklist data to waAIf Intelligence Cloud without explicit authorization and a terms review.
- **Unresolved:** validate the precise licenses and notices of individual remediation components and Hub assets before incorporating any files.

## Wordfence Intelligence

- The current vulnerability data feed is **V3**, which requires a Wordfence account and Bearer API key. The published V1/V2 deprecation notice states those versions were to stop serving vulnerability data on March 9, 2026.
- The V3 feed is documented as free for personal and commercial use, with rate limits (HTTP 429 on excess requests) and contractual terms.
- Vulnerability records can carry a `copyrights` object with multiple rightsholders, notices, license texts, and URLs. Wordfence documents record hyperlinks and reproduced notices as conditions for distributing covered information; MITRE attribution must be displayed where relevant.
- **Decision:** implement a V3-only, user-configured local connector after source contract review. Never embed or share an API key. Preserve per-record source URLs, attribution, and rights metadata. Do not assume a hosted redistribution service is automatically permitted just because commercial API consumption is free.
- **Unresolved:** verify contractual rights for the exact Intelligence Cloud data redistribution and caching model; seek clarification from the provider before enabling it.

## Source rights model (proposal)

A normalized intelligence record should preserve:

```json
{
  "source_id": "example",
  "source_record_id": "record-id",
  "source_url": "https://example.invalid/record",
  "observed_at": null,
  "ingested_at": "2026-10-20T00:00:00Z",
  "expires_at": null,
  "attribution": [],
  "license_id": null,
  "terms_url": null,
  "permitted_uses": {
    "local_analysis": "unverified",
    "cloud_ingestion": "unverified",
    "redistribution": "unverified",
    "commercial_service": "unverified"
  }
}
```

Use explicit `allowed | denied | unverified` permission states, **default-deny** for export and redistribution, and record the terms version/date reviewed. Source rights must be assessed independently for API access, copying, transformation, aggregation, caching, and customer-facing distribution. Derived data must not automatically lose upstream restrictions.

## Product boundaries

1. **Community Edition:** may ingest user-authorized sources locally subject to their terms; optional connectors cannot be mandatory for local detection.
2. **Intelligence Cloud:** must not mirror third-party curated feeds by default. Prefer waAIf's own observations and derived signals, with privacy and poisoning controls.
3. **Response Engine:** external indicators remain evidence, not unconditional mitigation instructions.
4. **Audit:** record origin, timestamp, confidence, rights and downstream uses.

## Primary references

- CrowdSec engine and license: https://github.com/crowdsecurity/crowdsec
- CrowdSec Hub: https://github.com/crowdsecurity/hub
- CrowdSec community blocklist: https://docs.crowdsec.net/docs/central_api/community_blocklist/
- CrowdSec Console pricing / third-party use: https://app.crowdsec.net/pricing
- Wordfence V3 feed: https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/
- Wordfence V1/V2 deprecation notice: https://www.wordfence.com/help/wordfence-intelligence/v2-accessing-and-consuming-the-vulnerability-data-feed/
- Wordfence terms (updated January 26, 2026): https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/

## Remaining verification

- [ ] Confirm the licensing of each specific CrowdSec remediation component selected for integration.
- [ ] Confirm Wordfence SaaS redistribution and cache permissions with the provider.
- [ ] Design and run the comparative detection/performance benchmark.
