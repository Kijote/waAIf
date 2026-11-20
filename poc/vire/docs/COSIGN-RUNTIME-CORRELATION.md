# Cosign-to-runtime evidence correlation

## Purpose

After the **trusted host** successfully runs `collector/verify_sigstore.sh` with exact certificate identity and OIDC issuer policy, `scanner/cosign_binding.py` correlates its verified CycloneDX in-toto payload with a locally supplied SBOM and the Docker runtime inventory.

The parser accepts Cosign JSONL entries with base64-encoded `payload` (or already-decoded JSON objects). It requires:
1. A matching Compose project and service with exactly one runtime container.
2. A matching immutable `sha256:` digest among observed Docker `RepoDigests`.
3. An in-toto Statement v1 with CycloneDX predicate type.
4. A subject digest equal to the requested image digest.
5. A predicate JSON document equal to the supplied CycloneDX SBOM document.

## Usage

```sh
# On trusted host: run the Cosign wrapper first (see SIGSTORE-VERIFICATION.md).
python3 scanner/cosign_binding.py \
  --sbom reports/image.cdx.json \
  --cosign-output reports/verified-cosign.jsonl \
  --runtime reports/runtime.json \
  --project demo --service web \
  --image-digest sha256:<64-lowercase-hex-characters>
```

## Critical trust boundary

**The Python correlation script DOES NOT verify Cosign signatures or identity.** A forged JSONL file could produce `matched` if supplied as trusted input. The result is only valid when the verified-output file is produced by a successful Cosign invocation under the operator's trusted execution boundary, protected from modification, and tied to the same immutable image reference. Do not expose this script as a standalone attestation verifier. A future integration should run Cosign and correlation in one trusted invocation with authenticated evidence transport.

`matched` means evidence consistency, not absence of vulnerabilities. The current collector is local and not authenticated, and runtime freshness and SBOM completeness are not established. This feature requires no paid API or subscription; registry/network access may be required for Cosign.

## Failure behavior

Missing or ambiguous runtime, malformed payload, missing attestation or SBOM mismatch results in `needs_verification`. A digest mismatch with runtime results in `drift_detected`. Do not trigger automatic remediation from either status.
