# Agent Instructions

- All repository content, documentation, code comments, commit messages, issues, PRs, logs, and UI copy must be written in English.
- Preserve the public Community Edition / private Intelligence Cloud separation described in `VISION.md`.
- Never introduce synchronous waAIf dependencies into the HTTP request path.
- Do not commit proprietary cloud implementation, credentials, customer traffic, secrets, or restricted third-party intelligence feeds.
- Do not assert third-party data redistribution rights without verifying source terms.
- Each implementation PR must include tests, failure behavior, performance considerations, and documentation updates.
- Automated mitigations must be scoped, reversible, time-limited, and auditable.
- The LLM must never execute unvalidated mitigation instructions directly.
