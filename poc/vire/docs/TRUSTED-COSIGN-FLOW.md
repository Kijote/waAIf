# Trusted Cosign verification and runtime correlation

## Purpose

`collector/verify_and_correlate.py` runs **Cosign itself** with a required exact certificate identity and OIDC issuer, immediately parses its verified CycloneDX attestation output, and correlates the signed subject and CycloneDX predicate with a local SBOM and Docker runtime inventory. It does not accept an externally supplied "verified" JSONL file.

## Requirements and execution

Install the free/open-source Cosign CLI on a trusted host. Ensure access to the OCI registry and Sigstore verification infrastructure, or a separately configured trusted offline verifier. No waAIf Cloud account or paid API is required.

```sh
cd poc/vire
python3 collector/docker_collector.py --output reports/runtime.json
python3 collector/verify_and_correlate.py \
  --image registry.example.org/team/app@sha256:<64-lowercase-hex> \
  --identity 'https://github.com/ORG/REPO/.github/workflows/build.yml@refs/heads/main' \
  --issuer 'https://token.actions.githubusercontent.com' \
  --sbom reports/image.cdx.json \
  --runtime reports/runtime.json \
  --project myproject --service web
```

All values are examples, not authorized identities. Use the actual signer policy and immutable image digest from the deployment.

## Trust model

- Cosign validates Sigstore attestation signatures, certificate identity and OIDC issuer under its configured trust roots.
- The correlation checks the signed in-toto subject digest, CycloneDX predicate JSON and the locally observed Docker `RepoDigests`.
- Cosign failure, timeout, malformed or missing output, ambiguous service, or absent evidence cannot yield `matched`.
- The script does not expose Cosign output as a reusable "verified" artifact and returns a nonzero exit code unless all checks match.
- No raw container secrets or HTTP traffic are uploaded by VIRE; Cosign itself may contact registry and verification endpoints.

## Known limitations

Cosign CLI version and trust roots are not yet pinned; the wrapper assumes the Cosign CLI's JSONL output shape and CycloneDX predicate type. A registry manifest digest may differ from an architecture-specific manifest digest. Docker's `RepoDigests` are not an authenticated runtime measurement. The local host and Python process are trusted; local compromise defeats this boundary. SBOM freshness, completeness, provenance quality, vulnerability matching and runtime attestation remain unverified. `matched` must not trigger automatic remediation.

## Tests

```sh
cd poc/vire
python3 -m unittest discover -s collector -v -p 'test_*.py'
```

Mocked Cosign tests require no network or paid services. A separate opt-in live integration test is needed before production claims.
