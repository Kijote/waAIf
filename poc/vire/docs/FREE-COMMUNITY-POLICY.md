# Free community operation policy

## Non-negotiable product requirement

The waAIf Community Edition and the complete VIRE local security analysis workflow must be usable without paid subscriptions, proprietary paid APIs, credit-card registration, or a mandatory SaaS account. Optional commercial hosting must never disable core local functionality.

## Architectural rules

1. **Local-first and offline-capable:** collection, inventory, SBOM ingestion, reconciliation, signature checks and reporting must work locally. External data synchronization is optional, cached and failure-tolerant.
2. **No paid dependency in the critical path:** every required external endpoint must be publicly available at no cost or have a documented free tier sufficient for the documented community workflow. Prefer fully open datasets and self-hostable mirrors over rate-limited free plans.
3. **Free-tier limits are explicit:** document quotas, authentication requirements, acceptable use, data retention, rate limits, commercial-use restrictions, redistribution terms and possible pricing changes. A free tier is not a permanent guarantee.
4. **Graceful degradation:** on quota exhaustion, outages or discontinued services, continue using local evidence and last-known trusted advisories, clearly marked with their retrieval timestamp. Never silently claim up-to-date CVE coverage.
5. **No required LLM billing:** rule-based and deterministic analysis is the default; LLM investigation is optional and can use local models.
6. **Licensing and redistribution:** validate licenses for tools, advisory feeds, schemas and databases before bundling or redistributing. Free access is not equivalent to open licensing.
7. **Privacy:** do not upload raw traffic, container configuration, private SBOMs or host metadata to third parties without explicit consent.
8. **Cost governance:** CI jobs, artifact storage and external traffic must have budgets/quotas; prefer community-accessible GitHub-hosted workflows for public repositories and reproducible local commands.
9. **No forced cloud:** optional waAIf Cloud features may be paid, but the Community Edition must retain detection, evidence, local correlation and manual response proposals.

## Candidate services and cost review

| Component | Candidate | Community strategy | Verification required before adoption |
| --- | --- | --- | --- |
| Container runtime | Docker Engine / compatible container runtime | Local operator installation | Product licensing and deployment context |
| SBOM generation | Syft (open-source CLI) | Local generation, no API | Current license and version pin |
| Signed attestations | Cosign / Sigstore | Local CLI, optional public trust infrastructure | Availability, terms, operational limits and offline verification plan |
| Vulnerability data | OSV public API / downloadable data | Cache locally, backoff, mirror where permitted | Rate limits, licensing, coverage and redistribution |
| CVE metadata | NVD public API / feeds | Prefer cached bulk sync over per-component requests | Rate limits, API key/free-access terms and redistribution |
| Vendor advisories | Distribution security trackers | Prefer publicly published feeds and mirrors | Per-vendor licensing, API quotas and backport semantics |
| CI | GitHub Actions for public repositories | Free-eligible public repo workflows and local test commands | GitHub policy, runner limits and abuse controls |
| LLM | Local open models (optional) | Never required for VIRE correctness | Model license and local compute requirements |

These are **candidates**, not a guarantee that all endpoints are free forever or that their terms permit every use. Each integration needs a checked, dated provider assessment before production activation.

## Provider acceptance checklist

For each external provider, document: official URL; purpose; owner; license/terms; free access or free tier; whether signup/card/API key is required; request quota; bulk-download option; caching/redistribution rights; last verification date; fallback; and privacy impact. Reject providers that cannot support a viable no-cost community path.

## Implementation gate

A PR adding a network endpoint, external SaaS, hosted API, paid SDK or mandatory cloud workflow must include an updated provider assessment and tests demonstrating local/offline behavior when that provider is unavailable.
