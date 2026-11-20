# Signed SBOM-to-runtime binding (PoC)

The verifier accepts an Ed25519-signed JSON envelope containing exactly four signed claims: `sbom_sha256`, `image_digest`, `project`, and `service`. The statement is encoded using sorted-key, compact UTF-8 JSON (`sort_keys=True`, `separators=(",", ":")`, `ensure_ascii=False`) before signing.

The verifier hashes the **raw SBOM file bytes** using SHA-256, verifies the signature against an operator-supplied trusted PEM public key, and compares the signed image digest with the Docker collector's observed repository digests.

## Verification
```sh
python3 scanner/signature.py \
  --sbom reports/image.cdx.json \
  --attestation reports/image.attestation.json \
  --trusted-key /secure/trusted-ed25519-public.pem \
  --runtime reports/runtime.json
```

No production signing keys are distributed with this repository. Signing is performed by an independent, trusted build pipeline, not by the VIRE scanner. The trusted key must be configured out of band; never accept a public key embedded in the same untrusted envelope.

## Interpretation
- `matched`: trusted signature, exact SBOM bytes, signed digest, and observed runtime repository digest agree.
- `drift_detected`: signature is valid but the observed digest differs.
- `needs_verification`: invalid signature, missing digest, ambiguous runtime identity or other insufficient evidence.

**Important:** `matched` means only that these pieces of evidence are consistent. It does not attest the Docker collector's authenticity, the SBOM generator's accuracy, software safety, or patch status. The prototype has no certificate chain, timestamp/freshness policy, key rotation, revocation, DSSE/in-toto compatibility, transparency log, or trusted CI identity. Do not use it for autonomous remediation or production security decisions.

The PoC uses a custom JSON envelope for experimentation. For production, prefer standard in-toto/DSSE attestations with Sigstore/cosign verification and a defined signer-identity policy.
