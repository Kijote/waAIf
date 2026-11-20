# SBOM-to-runtime digest binding

The prototype checks a separately supplied claim linking an SBOM to a Compose project/service and an immutable registry image digest against Docker's observed `RepoDigests`.

**A matching digest is not attestation.** The claim can be fabricated, and Docker's `RepoDigests` may include multiple registry references. Therefore the prototype never returns `matched` on this evidence alone; it reports `digest_consistent: true` alongside `needs_verification`.

A mismatched claimed digest is `drift_detected`. Missing, ambiguous or incomplete evidence is `needs_verification`.

## Next security gate
A trusted SBOM generation process must capture the actual immutable image digest, sign an attestation that binds the SBOM content hash to that digest, and verify the signer, signature, digest, freshness and deployment identity before a stronger result can be issued. Do not use unsigned operator-provided JSON as proof of provenance.

## Offline usage
```sh
python3 scanner/sbom.py fixtures/sample.cdx.json > /tmp/vire-sbom.json
python3 scanner/attest.py /tmp/vire-sbom.json reports/runtime.json fixtures/binding-sample.json
```

The binding fixture is illustrative and does not match arbitrary real deployments.
