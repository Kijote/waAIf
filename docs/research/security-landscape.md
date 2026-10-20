# Security Landscape: Initial Research Plan

## Baselines

| Source | Initial focus | Integration caution |
| --- | --- | --- |
| OWASP Core Rule Set | HTTP attack signatures and WAF rules | Review license and rule-update strategy |
| OWASP projects | Application threat categories and testing methodology | Distinguish guidance from machine-readable feeds |
| OpenSSF | Open-source supply-chain security context | Supply-chain scores are not HTTP attack evidence |
| CrowdSec | Behavioral scenarios, community signals, and remediation architecture | Review component licenses and data/API terms |
| Wordfence Intelligence | WordPress vulnerability context | Verify API terms and commercial redistribution rights |
| NVD / CVE / OSV | Vulnerability identifiers and affected products | Match to verified application technology |
| CISA KEV | Known exploited vulnerabilities | Prioritization, not proof of an observed exploit |
| MITRE ATT&CK / CAPEC | Techniques and attack patterns | Map observable evidence carefully |

## Evaluation criteria

1. Detectable signals and input data requirements.
2. Local-first operation and request-path overhead.
3. Precision, recall, explainability, and false-positive handling.
4. Data freshness, provenance, licensing, and redistribution rights.
5. Mitigation interoperability, TTL, and rollback.
6. Opportunities for cross-installation correlation.

## Research deliverable

Produce a sourced comparison matrix with verified licensing, deployment models, capabilities, integration constraints, and explicit differentiation hypotheses for waAIf. Do not assume public data is commercially redistributable.
