# Architecture

```text
HTTP clients -> existing nginx / Apache / WAF -> application
                        |
                        +-- asynchronous events --> Collector --> Analysis Engine
                                                                  |        |
                                                                  |        +--> Threat Intelligence Engine
                                                                  v
                                                             Response Engine
                                                                  |
                                                      validated mitigation adapters
                                                                  |
                                                    existing nginx / Apache / WAF

Optional: local intelligence connector <--> Intelligence Cloud
```

## Components

- **Collector:** structured HTTP access-log ingestion first; later optional eBPF or other sensors. Never synchronously query waAIf during request processing.
- **Analysis Engine (AE):** streaming statistics, endpoint baselines, sequence analysis, anomaly scoring, incident correlation, and optional LLM-assisted investigation.
- **Threat Intelligence Engine (TIE):** source adapters, license-aware ingestion, normalization, provenance, expiry, and graph relationships.
- **Response Engine (RE):** validates structured mitigation proposals against local policy; dry-runs, applies, verifies, expires, and rolls back changes.
- **Mitigation adapters:** nginx, Apache, ModSecurity/Coraza, and vendor WAF APIs. Adapters must not overwrite administrator-owned configuration.
- **Cloud connector:** optional, authenticated, privacy-preserving exchange of derived intelligence. Remote intelligence is advisory, never an unconditional block command.

## Safety and reliability

Collectors and analyzers have bounded buffers and resource budgets. Loss of waAIf must not disrupt the protected application's request path. Every mitigation must include ownership, scope, evidence, expiry, and a rollback mechanism. Mitigation state must reconcile after restart. Configuration changes must be validated before activation. A kill switch must disable automatic mitigation.

## Deployment separation

This repository contains only the Community Edition and public interoperability contracts. Proprietary cloud services, private datasets, commercial credentials, billing, and customer telemetry belong in a separate private repository and infrastructure.
