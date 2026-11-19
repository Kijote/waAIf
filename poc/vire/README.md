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

## Tests
```sh
cd poc/vire/scanner
python3 -m pip install -r requirements.txt
python3 -m unittest -v
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
