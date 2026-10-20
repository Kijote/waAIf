# Competitive Security Research — Issue #1

**Research date:** 2026-10-20  
**Status:** Initial primary-source review; integration feasibility and benchmarks remain open.

## Executive summary

CrowdSec is the closest architectural comparator: it already supports log-based behavioral scenarios, decoupled remediation, and shared malicious-IP intelligence. waAIf must demonstrate measurable incremental value rather than treating those capabilities as unique. OWASP CRS provides mature HTTP attack rules, while ModSecurity and Coraza provide WAF enforcement engines. Wordfence supplies WordPress vulnerability context; OpenSSF Scorecard provides supply-chain risk context, not HTTP attack evidence.

## Comparison matrix

| Project | Primary purpose | Detection input / mechanism | Response / integration | Licensing and data considerations | waAIf opportunity |
| --- | --- | --- | --- | --- | --- |
| OWASP CRS | Generic HTTP attack signatures | HTTP request inspection through ModSecurity-compatible WAF engines | ModSecurity, Coraza, compatible engines | CRS rules Apache-2.0; preserve notices and check specific distributions | Ingest matched-rule events as evidence; do not reinvent signature matching |
| CrowdSec | IDS/IPS, behavioral scenarios and collective IP intelligence | Logs and HTTP signals, parsers, scenarios, aggregation | Decoupled remediation components for firewall/proxy/CDN | Public detection scenarios described as MIT-licensed; verify per-component licenses and commercial API/blocklist terms separately | Multi-entity sequence correlation, transparent evidence, offline-first autonomous response with measurable added precision |
| Wordfence Intelligence | WordPress ecosystem vulnerability information | Version/plugin/theme vulnerability records, not general traffic behavior | Enrich technology-aware risk assessment | Public vulnerability feed documented for personal/commercial use subject to terms, copyright fields and attribution; re-check redistribution obligations for cloud products | Join observed requests with verified installed software and relevant vulnerabilities |
| OpenSSF Scorecard | Open-source supply-chain security posture | Automated repository checks and weekly API results | Enrich component inventory / exposure context | REST API data CDLA Permissive 2.0; code license is separate | Add optional supply-chain context without treating a poor score as evidence of active exploitation |

## Technical conclusions

1. **Detection is not exploitation proof.** CVEs, affected versions, and Scorecard ratings provide context. waAIf must connect them to concrete request/session evidence before raising incident confidence.
2. **CrowdSec is the primary benchmark.** Compare against its web scanning, brute-force, and distributed abuse scenarios with matched datasets. Evaluate detection delay, false positives, CPU, memory, and event loss.
3. **CRS should remain an external rule engine.** Consume audit/match events from an existing WAF where deployed; do not put waAIf into the request path or require WAF installation for basic detection.
4. **Local decisions remain authoritative.** Shared indicators from any network are advisory, source-attributed, expiring and checked against local policy.
5. **Keep source licensing distinct.** Open-source code licenses do not automatically grant rights to redistribute provider-curated blocklists, APIs, or vulnerability records. Maintain a source-by-source licensing register.
6. **Validate differentiators empirically.** Hypotheses include cross-IP/session temporal correlation, explainable AI-assisted investigation, policy simulation and reversible response. None is yet validated.

## Recommended integration sequence

1. Structured nginx/Apache log ingestion and reproducible detection benchmark.
2. Optional ingestion of OWASP CRS / ModSecurity / Coraza matched-rule events.
3. Compare detection on the same replay dataset against CrowdSec scenarios.
4. Introduce Wordfence vulnerability enrichment only when application technology/version evidence is available.
5. Evaluate OpenSSF Scorecard as optional inventory context, not an HTTP detector.
6. Define source-agnostic threat intelligence records with provenance, observed/ingested timestamps, confidence, expiry and license metadata.

## Primary sources

- OWASP CRS project: https://owasp.github.io/www-project-modsecurity-core-rule-set/
- OWASP CRS repository: https://github.com/coreruleset/coreruleset
- OWASP CRS developer guide: https://devguide.owasp.org/en/09-operations/04-crs/
- OWASP ModSecurity: https://owasp.org/projects/modsecurity
- OWASP Coraza: https://owasp.org/projects/coraza-web-application-firewall
- CrowdSec engine: https://github.com/crowdsecurity/crowdsec
- CrowdSec Hub: https://github.com/crowdsecurity/hub
- CrowdSec Service API: https://docs.crowdsec.net/u/console/api/intro/
- Wordfence Intelligence terms: https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/
- Wordfence feed documentation: https://www.wordfence.com/help/wordfence-intelligence/accessing-and-consuming-the-vulnerability-data-feed/
- OpenSSF Scorecard: https://github.com/ossf/scorecard
- OpenSSF Scorecard overview: https://openssf.org/projects/scorecard/

## Follow-up research / acceptance gaps

- [ ] Verify exact CrowdSec engine, hub, remediation, console and blocklist licensing separately.
- [ ] Verify Wordfence API/feed terms and downstream commercial redistribution requirements with legal review.
- [ ] Compare real deployment overhead and latency against CrowdSec and CRS on representative traffic.
- [ ] Design a replay dataset with legitimate and adversarial traffic and documented ground truth.
- [ ] Evaluate additional sources (CISA KEV, OSV, NVD, CAPEC) and their independent licensing constraints.
- [ ] Translate findings into adapter and detection specifications.

This is a sourced architectural baseline, **not** a completed performance study or legal opinion.
