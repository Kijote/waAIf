# VIRE implementation documentation index

This index tracks what exists, what is simulated, and what remains unverified.

| Area | Implementation | Documentation | Current limitation |
| --- | --- | --- | --- |
| Offline advisory demo | `scanner/scan.py` | `README.md` | Synthetic advisories, no live CVE claims |
| Declarative Docker/Compose inventory | `scanner/inventory.py` | `docs/INVENTORY-ARCHITECTURE.md` | No runtime inspection |
| Host Docker runtime collector | `collector/docker_collector.py` | `docs/DOCKER-COLLECTOR.md` | Requires local Docker CLI permissions |
| Runtime reconciliation | `scanner/reconcile.py` | `docs/RUNTIME-RECONCILIATION.md` | Provisional service identity and trust |
| CycloneDX SBOM ingestion | `scanner/sbom.py` | `docs/SBOM-INGESTION.md` | SBOM generated externally |
| Unsigned digest binding | `scanner/attest.py` | `docs/SBOM-RUNTIME-BINDING.md` | Never authenticates the SBOM |
| Custom Ed25519 signature verification | `scanner/signature.py` | `docs/SIGNED-SBOM-ATTESTATIONS.md` | Experimental envelope |
| DSSE/in-toto Ed25519 verification | `scanner/dsse.py` | `docs/DSSE-IN-TOTO.md` | No keyless Sigstore identity |
| Cosign host-side wrapper | `collector/verify_sigstore.sh` | `docs/SIGSTORE-VERIFICATION.md` | Not yet bound to VIRE runtime report |
| Free community dependency policy | n/a | `docs/FREE-COMMUNITY-POLICY.md` | Providers require ongoing terms checks |

## Delivery standard

Each new component must document: purpose, inputs/outputs and schemas, trust boundaries, installation, offline/local test commands, failure modes, privacy, dependencies and their licensing/cost, and what remains out of scope. Include CI tests for positive and negative paths. Update this index whenever a component changes.

## Current CI

`.github/workflows/vire-tests.yml` runs Python unit tests and Docker smoke tests. Green CI does not mean real CVE coverage or production readiness.

| Cosign SBOM/runtime correlation | `scanner/cosign_binding.py` | `docs/COSIGN-RUNTIME-CORRELATION.md` | Requires trusted Cosign output provenance; no standalone signature verification |

| Trusted Cosign verification and correlation | `collector/verify_and_correlate.py` | `docs/TRUSTED-COSIGN-FLOW.md` | Cosign CLI/trust roots not yet pinned; local runtime evidence unauthenticated |
