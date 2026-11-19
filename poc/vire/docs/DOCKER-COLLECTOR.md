# Host-side Docker runtime collector

## Security model
The collector is a **separate, opt-in host CLI**. It invokes the installed Docker CLI using the operator's existing permissions and exports a sanitized JSON document. It does not run inside the VIRE scanner container. Docker access is effectively privileged on typical rootful installations: **only execute this collector on hosts you administer and trust**.

No Docker socket is mounted into the VIRE scanner. No Docker credentials, environment variables, mount sources, secrets, or container logs are exported. The output contains container IDs, project/service labels, image IDs, image references, image repository digests and running state. Treat the output as sensitive infrastructure metadata and protect it (file mode 0600).

## Usage
```sh
cd poc/vire
python3 collector/docker_collector.py --output reports/runtime.json
```

Docker Engine and the Docker CLI must already be available on the host. The collector never starts, stops or changes containers.

To analyze a runtime export, supply it explicitly to the offline reconciliation command (do not commit the export). The sample Compose reconciliation service currently uses the synthetic `fixtures/runtime-sample.json`; change its input mount to your generated JSON when testing real infrastructure.

## Important evidence limitations
- Docker image IDs and `RepoDigests` are **not** automatically the expected deployment digest. The collector deliberately does not fabricate `expected_image_digest`.
- Compose labels are used to associate runtime containers with project/service names. The prototype matches the basename of the Compose config file; this is ambiguous when multiple projects use the same filename. Production must use normalized absolute/project-relative paths and project IDs.
- Image tags can be mutable. A matching tag is not enough for `matched`.
- The collector does not inspect package versions, OS provenance, SBOM, effective NGINX configuration, container networks or security policies.
- The exporter only collects containers with Docker Compose service labels.
- Docker CLI failures cause a nonzero exit; no incomplete inventory is silently treated as complete.
- Runtime data is not cryptographically authenticated or freshness-validated. Do not use this prototype for production security enforcement.
