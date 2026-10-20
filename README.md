# waAIf

**Don't wait. waAIf.**

**waAIf (Web Application AI Firewall)** is an open-source, local-first platform for **passive, asynchronous HTTP security anomaly detection and autonomous response**.

waAIf observes application traffic without sitting in the request/response path. It detects suspicious patterns, investigates incidents, and can activate scoped, temporary, reversible mitigations through existing **nginx, Apache, and WAF** infrastructure.

> **Project status:** Early architecture and research. The features described below are planned capabilities, not a claim of a production-ready release.

## How it works

```text
Internet --> nginx / Apache / WAF --> Application
                  |
                  +--> async event collector --> Analysis Engine
                                                   |
                                      Threat Intelligence Engine
                                                   |
                                             Response Engine
                                                   |
                                     validated mitigation adapters
                                                   |
                                           nginx / Apache / WAF

          Optional: Community Core <--> Intelligence Cloud
```

## Design principles

- **Out of the critical path:** no synchronous waAIf decision is required to serve HTTP traffic.
- **Local-first:** detection and response work independently of any cloud service.
- **Bounded overhead:** resource usage, backpressure, and event loss must be measured and controlled.
- **Explainable detection:** correlate HTTP behavior, statistical anomalies, and external intelligence with retained evidence.
- **Safe response:** validate, audit, expire, verify, and roll back every automated mitigation.
- **Vendor-independent:** integrate with existing reverse proxies and traditional WAFs rather than replacing them.
- **Privacy by default:** no request bodies, secrets, or personal information are shared with cloud services by default.

## Editions

| | waAIf Community Edition | waAIf Intelligence Cloud |
| --- | --- | --- |
| Repository | [Kijote/waAIf](https://github.com/Kijote/waAIf) (public) | Private service implementation |
| Model | Open-source, local-first | Optional commercial subscription |
| Passive event collection and local detection | Planned | Uses locally derived signals |
| Local mitigation adapters and audit trail | Planned | Not required |
| Public threat-intelligence integration | Planned | Enriched collective intelligence |
| Cross-installation correlation and emerging campaigns | Not included | Planned |

The Community Edition is intended to remain useful and fully functional without a subscription. The commercial service provides intelligence that cannot be derived from one installation alone. Cloud intelligence is advisory and cannot bypass local mitigation policies.

## Security research foundations

The initial research includes [OWASP Core Rule Set](https://coreruleset.org/), [OpenSSF](https://openssf.org/), [CrowdSec](https://www.crowdsec.net/), [Wordfence Intelligence](https://www.wordfence.com/threat-intel/), and public vulnerability sources such as CVE/NVD, OSV, and CISA KEV. Third-party license and redistribution rights must be reviewed before integration.

See [Security Landscape](docs/research/security-landscape.md).

## Documentation

- [Vision](VISION.md)
- [Architecture](ARCHITECTURE.md)
- [Roadmap](ROADMAP.md)
- [Agent instructions](AGENTS.md)
- [Security research](docs/research/security-landscape.md)
- [Open issues](https://github.com/Kijote/waAIf/issues)

## Contributing

This project is in its design and research phase. Contributions and discussions are welcome through GitHub issues. All project documentation, issues, pull requests, source comments, and user-facing content must be written in **English**.

## License

**Apache License 2.0 is the intended license for the Community Edition.** The license file must be added before treating the repository as licensed under Apache 2.0. Until then, ordinary copyright restrictions apply.
