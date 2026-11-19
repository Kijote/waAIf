"""Opt-in host-side Docker inventory exporter.

Runs on the operator's host with their existing Docker CLI permissions.
Never passes Docker Engine access to the VIRE analysis container.
"""
import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

def docker_json(*args):
    result = subprocess.run(["docker", *args], capture_output=True, text=True, check=True, timeout=30)
    return json.loads(result.stdout)

def collect():
    ids = subprocess.run(["docker", "ps", "-aq", "--filter", "label=com.docker.compose.service"],
                         capture_output=True, text=True, check=True, timeout=30).stdout.split()
    if not ids:
        return {"schema_version": "0.1.0", "source": "docker_cli_host", "collected_at": datetime.now(timezone.utc).isoformat(), "services": []}
    containers = docker_json("inspect", *ids)
    images = {}
    services = []
    for container in containers:
        config = container.get("Config") or {}
        labels = config.get("Labels") or {}
        service = labels.get("com.docker.compose.service")
        if not service:
            continue
        image_id = container.get("Image")
        if image_id and image_id not in images:
            images[image_id] = docker_json("image", "inspect", image_id)[0]
        image = images.get(image_id, {})
        # RepoDigests are registry references, not guaranteed deployment expectations.
        repo_digests = image.get("RepoDigests") or []
        compose_files = labels.get("com.docker.compose.project.config_files", "")
        compose_file = Path(compose_files.split(",")[0]).name if compose_files else ""
        services.append({
            "compose_file": compose_file,
            "service": service,
            "project": labels.get("com.docker.compose.project"),
            "container_id": container.get("Id"),
            "running": bool((container.get("State") or {}).get("Running")),
            "declared_image": config.get("Image"),
            "image_id": image_id,
            "repo_digests": sorted(repo_digests),
            # Deliberately absent: expected_image_digest. Must come from trusted deployment manifest.
        })
    return {"schema_version": "0.1.0", "source": "docker_cli_host",
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "services": sorted(services, key=lambda x: (x["project"] or "", x["service"], x["container_id"] or ""))}

def main():
    parser = argparse.ArgumentParser(description="Export sanitized Docker Compose runtime inventory")
    parser.add_argument("--output", required=True, help="Local JSON output file (do not commit)")
    args = parser.parse_args()
    report = collect()
    path = Path(args.output)
    if path.exists() and path.is_symlink():
        raise ValueError("Refusing to overwrite symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
    path.chmod(0o600)
    print(f"Exported {len(report['services'])} Compose container(s) to {path}")

if __name__ == "__main__":
    main()
