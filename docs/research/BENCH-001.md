# BENCH-001: Reproducible Passive HTTP Security Benchmark

**Status:** Proposed protocol — no measurements have been performed.  
**Research issue:** [#1](https://github.com/Kijote/waAIf/issues/1)  
**Implementation tracking:** [#4](https://github.com/Kijote/waAIf/issues/4)

## Research questions

1. Does waAIf detect malicious HTTP behavior missed by a comparable CrowdSec configuration?
2. At matched recall, can waAIf reduce false-positive alerts and unsafe mitigation proposals?
3. What incremental CPU, RSS, HTTP latency, throughput and event-loss cost does each architecture impose?
4. Does mitigation execute, expire and roll back safely, including during failure or restart?

## Hypotheses (not results)

- **H1:** Cross-session and cross-IP temporal correlation may improve recall on distributed, low-and-slow attack campaigns.
- **H2:** Evidence-based incident aggregation may reduce redundant alerts and false positives at equivalent recall.
- **H3:** Passive, asynchronous collection can keep request-path overhead bounded, subject to log-write and system-resource contention.
- **H4:** Structured mitigation proposals with TTL and rollback can reduce unsafe or stale blocks.

## Comparable deployment modes

- **B0 — nginx only:** same access-log configuration and log destination used in subsequent variants; no external detector.
- **B1 — nginx + CrowdSec:** pinned CrowdSec version, explicit parser/scenario set, local analysis, no cloud reputation contribution unless separately measured and authorized.
- **B2 — nginx + waAIf:** pinned commit and comparable local-only event inputs. No additional WAF audit signals unless provided to both systems.
- **B3 — nginx + both (optional):** investigate contention, not used to claim B1/B2 superiority.

Use isolated, equivalently provisioned hosts/containers and record CPU limits, storage, kernel, nginx build, TLS settings, detector configuration and network topology. Randomize run order; repeat each workload at least five times after warm-up. Preserve logs and configuration checksums.

## Dataset and ground truth

Use a locally controlled application and synthetic or consented traffic only. Never test against third-party infrastructure.

| Workload | Legitimate / malicious label | Required characteristics |
| --- | --- | --- |
| Normal browsing and API use | Legitimate | Diverse routes, clients, status codes, authenticated sessions |
| High-volume legitimate traffic | Legitimate | Bursts, batch clients, retry storms, crawlers explicitly authorized |
| Credential stuffing / brute force | Malicious | Rate variation and distributed source addresses in lab |
| HTTP reconnaissance | Malicious | Enumeration, unusual routes, error bursts |
| Low-and-slow distributed probing | Malicious | Multiple IPs, sparse per-IP activity, shared target patterns |
| Known attack-shaped requests | Malicious | Benign lab endpoints and recorded ground-truth attack intent |
| Mixed concurrent workload | Both | Overlapping attack and legitimate behavior |
| Sensor overload / log rotation | Operational | Backpressure, dropped events, crash/restart and disk-pressure conditions |

Ground truth must identify attack campaign ID, event IDs, start/end times, source identities, target, intent, and expected detection scope. Include at least one held-out dataset not used for tuning. Keep the proportion of attacks explicit; report per-scenario and aggregate results separately.

## Fairness controls

- Use identical event fields and collection timing for both detectors.
- Pin rule/scenario sets and document tuning effort and thresholds.
- Compare both default configuration and a separately labeled tuned configuration.
- Do not give waAIf privileged ground-truth labels, extra threat feeds or application metadata absent from CrowdSec.
- Evaluate per-event, per-incident and per-campaign matching separately; publish matching windows and deduplication rules before testing.
- Calibrate alert thresholds on a training split only; evaluate on an untouched test split.
- Report 95% confidence intervals where feasible and raw confusion matrices; do not claim statistical significance from a single run.

## Metrics

### Detection
- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1, false positives per 10,000 legitimate requests, and false positives per legitimate client-day
- Detection delay from first relevant malicious event (p50/p95/p99)
- Alert duplication per campaign and missed-campaign count
- Precision-recall curves or equivalent threshold sweeps, with predeclared operating points

### Performance
- nginx request latency p50/p95/p99 and throughput relative to B0
- Collector/analyzer CPU-seconds per 1M requests and peak/steady RSS
- Ingestion lag p50/p95/p99, queue depth, event drops per 1M events
- Storage bytes written per 1M requests and restart catch-up time
- Overload behavior: whether the application remains available and the detector degrades predictably

### Mitigation
- Proposal-to-activation latency
- Unauthorized or overbroad mitigation count (target: zero in tests)
- TTL expiry accuracy, rollback success rate and time
- Behavior on adapter failure, invalid configuration, repeated action and process restart
- Audit completeness (evidence, actor, scope, TTL, result)

## Acceptance gates

**Protocol readiness**
- [ ] Workload generator, traffic traces and replay instructions checked into the repository without secrets.
- [ ] Ground-truth format, splits and scenario manifest documented.
- [ ] Baseline and CrowdSec configurations version-pinned and runnable.
- [ ] waAIf event adapter and replay interface implemented.
- [ ] Reproducible environment and result artifact schema published.

**Execution readiness**
- [ ] At least five repeated runs per configuration/workload.
- [ ] No production or third-party targets.
- [ ] Raw results, configurations, test environment and scripts committed or linked to reproducible artifacts.
- [ ] Comparison reports uncertainty and separates default/tuned results.
- [ ] All claims in README and marketing trace back to measured results.

## Suggested implementation layout

```text
benchmarks/http-security/
  README.md
  scenarios/
  configs/
    nginx/
    crowdsec/
    waaif/
  fixtures/
  scripts/
  schemas/
  results/          # sanitized reproducible outputs only
```

## Follow-on implementation tasks

1. Create an isolated docker-compose lab with nginx and a deterministic test application.
2. Generate labeled request traces and a source-of-truth campaign manifest.
3. Build the shared log event normalizer and replay harness.
4. Pin and run CrowdSec scenarios; document supported signals.
5. Connect the future waAIf Analysis Engine and Response Engine.
6. Produce comparable machine-readable results and a human-readable report.

**No numeric performance, detection, or safety claims should be published before actual measurements.**
