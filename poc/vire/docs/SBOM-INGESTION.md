# SBOM ingestion — PoC 001

## Scope
VIRE accepts a **pre-generated CycloneDX JSON** software bill of materials and normalizes its components into a deterministic JSON inventory. It does not generate SBOMs, access Docker Engine, fetch CVEs or assert vulnerability status.

## Generate an SBOM outside the scanner
An operator may use an established SBOM generator (for example, Syft) against an image or an immutable image digest. Review the generator's installation and trust model separately.

```sh
# Example only; requires a separately installed Syft CLI
syft nginx:1.27-alpine -o cyclonedx-json > reports/image.cdx.json
```

For production correlation, record the exact scanned image digest, SBOM generator version, creation timestamp and evidence provenance. A mutable tag is insufficient to prove that the SBOM describes the running image.

## Analyze offline
```sh
cd poc/vire
docker compose --profile sbom run --build --rm -T sbom
```

The default input is the synthetic `fixtures/sample.cdx.json`. To use a generated SBOM in `reports/`, set `SBOM_INPUT=/runtime/image.cdx.json`.

## Trust boundaries and limitations
- Read-only mounts, no Docker socket, no network, no remediation.
- CycloneDX `components` are parsed as untrusted data, with a 20 MiB input limit.
- Only components with nonempty name and version are emitted; excluded entries are not evidence of absence.
- A package URL (purl) is an identifier, not proof of distro/vendor origin or backport status.
- The current parser does not resolve dependency graphs, hashes, component relationships, signatures or nested SBOM references.
- Do not use this report alone for production vulnerability decisions.

## Next step
Correlate SBOM provenance and immutable image digest with trusted runtime observations. Then implement vendor/distro advisory adapters and backport-aware applicability with explicit `needs_verification` for missing evidence.
