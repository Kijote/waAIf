# VIRE Docker PoC 001

Offline, read-only demonstration of vulnerability applicability and **declarative infrastructure inventory**. Not a live CVE scanner.

## Requirements
Docker Engine and Docker Compose v2.

## Run applicability demonstration
```sh
cd poc/vire
mkdir -p reports
chmod 777 reports # temporary demo-only permissions for unprivileged UID
docker compose up --build --abort-on-container-exit
cat reports/report.json
docker compose down
```

All advisory identifiers and affected version ranges in `fixtures/advisories.json` are **synthetic**.

## Inventory Dockerfile and Compose files
```sh
cd poc/vire
docker compose --profile inventory run --build --rm inventory
```

The inventory command reads the repository root from `/project`, mounted read-only, and prints JSON. It does **not** query Docker Engine, inspect the running nginx container, resolve all Compose features, or prove that declared images are deployed.

To scan another directory, explicitly replace the `../..:/project:ro` bind mount in the Compose inventory service with the desired absolute project path. Do not mount secrets or unrelated directories.

## Offline runtime reconciliation

```sh
cd poc/vire
docker compose --profile reconcile run --build --rm reconcile
```

This compares declarative Compose services against a **synthetic** runtime fixture; it does not query Docker Engine. Results are `matched`, `drift_detected`, or `needs_verification`. See [Runtime Reconciliation](docs/RUNTIME-RECONCILIATION.md).

## Real Docker inventory (opt-in, host-side)

```sh
cd poc/vire
python3 collector/docker_collector.py --output reports/runtime.json
RUNTIME_INPUT=/runtime/runtime.json docker compose --profile reconcile run --build --rm -T reconcile
```

The collector uses the host Docker CLI, not a socket mounted in VIRE. It exports sanitized runtime metadata only. Without an independently established expected digest, a matching tag is **not** considered verified. See [Docker Collector](docs/DOCKER-COLLECTOR.md).

## Offline SBOM ingestion

```sh
cd poc/vire
docker compose --profile sbom run --build --rm -T sbom
```

The default input is a synthetic CycloneDX JSON fixture. You can generate an SBOM externally and set `SBOM_INPUT=/runtime/image.cdx.json` after placing it in `reports/`. See [SBOM Ingestion](docs/SBOM-INGESTION.md).

## SBOM-to-runtime digest checks

Use `python3 scanner/attest.py SBOM_INVENTORY_JSON RUNTIME_JSON BINDING_JSON` to check whether a separately claimed SBOM image digest agrees with observed Docker registry digests. Matching digest evidence alone **never** authenticates an SBOM. See [SBOM Runtime Binding](docs/SBOM-RUNTIME-BINDING.md).

## Tests
```sh
cd poc/vire/scanner
python3 -m pip install -r requirements.txt
python3 -m unittest -v
python3 -m unittest discover -s ../collector -v -p 'test_*.py'
```

Tests and Docker builds have not yet been executed in the development environment.

## Security and architecture
See [Infrastructure Inventory Architecture](docs/INVENTORY-ARCHITECTURE.md).

- No Docker socket, no network access to the scanner, no elevated privileges.
- The target NGINX container is not inspected.
- No production vulnerability conclusions and no remediation execution.
- `chmod 777` is a **temporary demo workaround** and must be replaced by UID-aligned output permissions before production use.

## Roadmap
1. Versioned evidence schema and declarative/runtime reconciliation.
2. Narrowly scoped runtime collector, package database and image digest evidence.
3. NGINX effective configuration collection.
4. Real NVD, CISA KEV, OSV and vendor advisory feeds with backport-aware matching.
5. Deterministic remediation plan, operator approval, verification and rollback.

## Signed SBOM binding

Verify an independently signed SBOM-to-image claim with an explicitly trusted Ed25519 public key. No signing keys are bundled. See [Signed SBOM Attestations](docs/SIGNED-SBOM-ATTESTATIONS.md).

```sh
python3 scanner/signature.py --sbom reports/image.cdx.json --attestation reports/image.attestation.json --trusted-key /secure/trusted-ed25519-public.pem --runtime reports/runtime.json
```

## Offline DSSE / in-toto verification

`scanner/dsse.py` verifies an Ed25519 DSSE envelope containing a constrained in-toto Statement v1, using a separately configured public key. This is not Sigstore keyless verification. See [DSSE / in-toto](docs/DSSE-IN-TOTO.md).

## Sigstore / Cosign keyless verification (opt-in)

`collector/verify_sigstore.sh` invokes the official Cosign CLI on a trusted host with a pinned image digest and explicit certificate identity / OIDC issuer. It does **not** yet establish a VIRE `matched` result; see [Sigstore Verification](docs/SIGSTORE-VERIFICATION.md).

## Community access and documentation

VIRE's local community workflow must remain free of mandatory paid APIs, subscriptions and SaaS accounts. Every new external dependency requires a reviewed free-access path and offline fallback. See [Free Community Policy](docs/FREE-COMMUNITY-POLICY.md) and [Implementation Index](docs/IMPLEMENTATION-INDEX.md).

## Correlate Cosign-verified SBOM evidence with runtime

`scanner/cosign_binding.py` compares the verified CycloneDX predicate, signed image subject and Docker runtime digest. **It does not independently verify signatures**: supply only output from a trusted successful Cosign verification. See [Cosign Runtime Correlation](docs/COSIGN-RUNTIME-CORRELATION.md).
