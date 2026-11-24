"""Best-effort declarative inventory. Never invokes Docker or executes project code."""
import json
import re
import sys
from pathlib import Path

import yaml

FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", re.I)
ARG = re.compile(r"^\s*ARG\s+(\w+)(?:=(.*))?$", re.I)
VAR = re.compile(r"\$\{?(\w+)\}?")
COMPOSE_NAMES = {"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}

def dockerfile_images(path):
    args, images = {}, []
    for line in path.read_text(errors="replace").splitlines():
        match = ARG.match(line)
        if match:
            args[match.group(1)] = match.group(2)
        match = FROM.match(line)
        if match:
            raw = match.group(1)
            resolved = VAR.sub(lambda m: args.get(m.group(1)) or m.group(0), raw)
            images.append({"reference": resolved, "fully_resolved": "$" not in resolved})
    return images

def compose_services(path):
    # Safe YAML parsing, without Compose interpolation, includes, or extends.
    data = yaml.safe_load(path.read_text())
    if not isinstance(data, dict) or not isinstance(data.get("services"), dict):
        raise ValueError("Compose services must be a mapping")
    result = []
    for name, service in data["services"].items():
        if not isinstance(service, dict):
            continue
        build = service.get("build")
        result.append({
            "service": str(name),
            "image": service.get("image"),
            "build_context": build.get("context") if isinstance(build, dict) else build,
            "dockerfile": build.get("dockerfile", "Dockerfile") if isinstance(build, dict) else ("Dockerfile" if build else None),
            "declared_ports": service.get("ports", []),
        })
    return result

def collect(root):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Inventory root must be a directory")
    files = sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink())
    dockerfiles = [p for p in files if p.name == "Dockerfile" or p.name.startswith("Dockerfile.")]
    composes = [p for p in files if p.name in COMPOSE_NAMES]
    report = {"schema_version": "0.1.0", "mode": "declarative_only", "dockerfiles": [], "compose_files": [], "errors": [],
              "limitations": ["No Docker Engine access or runtime verification", "No package/SBOM or effective nginx configuration inspection", "Compose variables, extends, and includes are not resolved", "Image tags are mutable; declared images do not prove running versions"]}
    for p in dockerfiles:
        relative = str(p.relative_to(root))
        try:
            report["dockerfiles"].append({"path": relative, "base_images": dockerfile_images(p)})
        except (OSError, UnicodeError) as exc:
            report["errors"].append({"path": relative, "error": str(exc)})
    for p in composes:
        relative = str(p.relative_to(root))
        try:
            report["compose_files"].append({"path": relative, "services": compose_services(p)})
        except (OSError, ValueError, yaml.YAMLError) as exc:
            report["errors"].append({"path": relative, "error": str(exc)})
    return report

if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "/project"
    print(json.dumps(collect(root), indent=2))
