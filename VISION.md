# waAIf Vision

**Don't wait. waAIf.**

waAIf (Web Application AI Firewall) is a local-first, open-source platform for passive HTTP security anomaly detection and asynchronous response.

## Product boundary

- **Community Edition (this public repository):** fully functional local collection, analysis, incident investigation, policy management, response adapters, auditability, and optional cloud connector. No subscription is required for local protection.
- **Intelligence Cloud (separate private service):** optional paid, centrally operated cross-installation threat correlation, reputation, emerging-campaign detection, and intelligence distribution.
- Cloud unavailability must not prevent local detection or compromise the protected application.

## Non-negotiable principles

1. Never place waAIf in the HTTP request/response critical path.
2. Observe asynchronously with bounded CPU, memory, disk, and queue usage; measure overhead and event loss.
3. Apply mitigations through existing nginx, Apache, or WAF mechanisms using explicit adapters.
4. Keep mitigations scoped, auditable, expiring, testable, and reversible.
5. Treat traffic, external feeds, and LLM outputs as untrusted input.
6. Do not export request bodies, secrets, or personal data by default.
7. Preserve provenance, timestamps, evidence, and confidence for every security conclusion.
8. Keep all project materials in English.
