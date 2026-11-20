# DSSE / in-toto verification (offline prototype)

The verifier accepts a DSSE envelope with `payloadType=application/vnd.in-toto+json`, verifies the Ed25519 signature over the **DSSE pre-authentication encoding (PAE)**, and parses a constrained in-toto Statement v1.

The signed statement has one image subject with `digest.sha256` and the custom predicate type `https://waaif.invalid/vire/sbom-binding/v1` containing `sbomSha256`, `project`, and `service`. The SBOM hash covers the original file bytes.

The verifier compares the signed image digest with the observed Docker `RepoDigests` for exactly one matching Compose project/service.

## Usage
```sh
python3 scanner/dsse.py \
  --sbom reports/image.cdx.json \
  --envelope reports/image.dsse.json \
  --trusted-key /secure/ed25519-public.pem \
  --runtime reports/runtime.json
```

The trust anchor must be supplied separately. No private keys or sample trusted keys are committed. This PoC **verifies** envelopes but does not issue attestations.

## Security boundary
This is **not full Sigstore verification**. There is no Fulcio certificate validation, OIDC issuer/subject policy, Rekor inclusion proof, timestamp freshness, revocation, key rotation, SLSA provenance, or verification of the Docker collector's authenticity. A `matched` status means only that the configured public key signed a statement consistent with the SBOM bytes and reported runtime digest. It does not prove vulnerability absence or SBOM completeness.

For production, integrate an established Sigstore/cosign verifier with explicit trusted roots and identity policies rather than reimplementing keyless PKI.
