# Roadmap

## Phase 0 — Research and contracts

- Compare OWASP CRS, OpenSSF, CrowdSec, Wordfence, and public vulnerability/intelligence sources.
- Record licenses, API terms, redistribution rights, update frequency, and applicability to HTTP detection.
- Define event, evidence, incident, and mitigation schemas; define trust boundaries and threat model.

## Phase 1 — Passive MVP

- Implement structured nginx access-log collector with backpressure and resource limits.
- Establish repeatable CPU, memory, request-latency, and event-loss benchmarks.
- Implement local statistical baselines, anomaly detection, and incident timeline.

## Phase 2 — Safe response

- Define provider-independent mitigation proposals.
- Implement policy validation, dry-run, TTL, audit log, rollback, and nginx adapter.
- Add Apache and traditional WAF adapters.

## Phase 3 — Intelligence and investigation

- Integrate selected legally reusable public threat intelligence sources.
- Correlate indicators, techniques, events, vulnerabilities, and mitigations with provenance.
- Add optional LLM-assisted investigation, isolated from direct enforcement.

## Phase 4 — Optional commercial cloud

- Publish a versioned intelligence exchange protocol in this repository.
- Develop the central Intelligence Cloud separately in a private repository.
- Validate consent, privacy, anti-poisoning controls, and subscription boundaries.
