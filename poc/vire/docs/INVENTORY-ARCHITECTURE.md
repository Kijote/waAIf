# Infrastructure Inventory Engine — PoC architecture

## Purpose and trust boundaries
VIRE combines **declarative evidence** (Dockerfile and Compose) with **runtime evidence** (running image digest, packages, SBOM and effective configuration). These are different evidence classes and must not be silently treated as interchangeable.

PoC 001 implements only declarative discovery. It does not inspect the running NGINX container and does not claim that a declared image is deployed. It does not query CVE services or apply patches.

### Data flow
1. Operator explicitly supplies a project directory.
2. Scanner reads it through a read-only bind mount.
3. Safe YAML parser reads Compose files; text parser reads Dockerfile FROM and ARG defaults.
4. Inventory JSON reports source paths, image references, ports and unresolved values.
5. A later reconciliation component will compare this against separately collected runtime facts.
6. The vulnerability engine will evaluate applicability only when trustworthy version, configuration and vendor advisory evidence are available.

### Security
- Never mount the Docker socket into the scanner.
- Scanner runs as non-root, drops capabilities, disallows privilege escalation and has no network.
- Input files are untrusted. Do not execute Dockerfile RUN commands, Compose hooks, project scripts or interpolated shell.
- Do not automatically follow symlinked files. For production, add resource budgets, file-size limits and directory exclusions to prevent resource exhaustion.
- Treat image tags as mutable; require immutable digests for reproducible runtime correlation.
- Treat all scanner output as untrusted observations; do not feed arbitrary repository text into privileged execution.
- Runtime inventory requires a separate narrowly scoped collector, ideally through a rootless Docker API proxy or externally generated signed inventory. A read-only mount of docker.sock is **not** a security boundary.
- No remediation execution or automatic service restarts in this PoC.

### Evidence model
For every observation retain: source kind, relative file path, declared value, resolution state and collection time (future schema extension). Runtime records must include container ID, immutable image digest, OS release, package origin/revision, and collection provenance. Missing or contradictory evidence must yield `needs_verification`, never a fabricated `not_affected`.

### Known limitations
- Compose includes, extends, profiles, anchors across files, env-file resolution and variable interpolation are not fully implemented.
- Dockerfile parsing is intentionally limited to FROM and ARG defaults, not full Dockerfile grammar.
- Symlinked files are skipped, but directory traversal and resource limits need hardening.
- No SBOM, package database, nginx -T, running image inspection or drift detection yet.
- No vulnerability feed connectors; current advisory fixtures are synthetic.
- This PoC is a development prototype, not a production vulnerability scanner.

## Next milestones
1. Define versioned inventory evidence and reconciliation schemas, including tests for missing, stale and conflicting observations.
2. Add a read-only runtime collector with least-privilege access and digest correlation.
3. Parse effective NGINX configuration in a sandboxed, read-only process.
4. Add vendor advisories and NVD/CISA/OSV connectors with provenance, freshness and distro backport matching.
5. Generate deterministic remediation plans requiring explicit approval before any action.
