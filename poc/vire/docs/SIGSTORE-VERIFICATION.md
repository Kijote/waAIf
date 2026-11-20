# Sigstore verification boundary (host-side, opt-in)

The `collector/verify_sigstore.sh` wrapper invokes the **official cosign CLI** to verify a CycloneDX attestation for an immutable OCI image reference. It requires an **exact certificate identity** and **exact OIDC issuer** configured by the operator. No wildcard identities are accepted by this wrapper. The official Cosign verifier, not VIRE's Python code, validates the Sigstore trust chain and transparency evidence according to its version and configuration.

## Requirements
- A separately installed, trusted Cosign CLI.
- Access to the relevant OCI registry and Sigstore verification services, or a separately configured trusted offline verification environment.
- A published CycloneDX attestation for the immutable image digest.
- An explicit trusted certificate identity and OIDC issuer established from the authorized build pipeline.

## Example
```sh
export IMAGE_DIGEST='registry.example.org/team/app@sha256:<64 lowercase hex chars>'
export CERT_IDENTITY='https://github.com/ORG/REPO/.github/workflows/build.yml@refs/heads/main'
export CERT_OIDC_ISSUER='https://token.actions.githubusercontent.com'
export OUTPUT='reports/verified-cosign.jsonl'
bash collector/verify_sigstore.sh
```

The values above are placeholders, not a pre-approved policy. Never trust an issuer or identity copied from an untrusted attestation.

## Trust boundary
This wrapper is run on the operator's trusted host or build infrastructure, **not** in the isolated VIRE scanner. Cosign can make network requests; the VIRE analysis container remains offline and without Docker socket access.

**Important limitation:** the wrapper stores Cosign's verified output but does not yet bind its payload to VIRE's normalized SBOM inventory or the Docker runtime collector. A successful Cosign invocation alone must **not** be translated to a VIRE `matched` result. That requires extracting and checking the verified attestation subject, predicate, SBOM hash, and actual runtime image digest, plus evidence freshness.

The output may contain sensitive infrastructure metadata; keep it out of Git and restrict access. Verification policy must pin Cosign version and trusted roots, and define revocation, identity, timestamp, and provenance requirements before production use.
