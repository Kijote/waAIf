"""Offline CycloneDX JSON SBOM ingestion; no network or container privileges."""
import argparse
import json
from pathlib import Path

MAX_BYTES = 20 * 1024 * 1024

def read_sbom(path):
    path = Path(path)
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("SBOM exceeds 20 MiB limit")
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("bomFormat") != "CycloneDX" or not isinstance(document.get("components"), list):
        raise ValueError("Expected CycloneDX JSON with components array")
    components = []
    for component in document["components"]:
        if not isinstance(component, dict):
            continue
        name, version = component.get("name"), component.get("version")
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            continue
        purl = component.get("purl")
        components.append({
            "name": name,
            "version": version,
            "type": component.get("type"),
            "purl": purl if isinstance(purl, str) else None,
            "bom_ref": component.get("bom-ref"),
            "source": "cyclonedx",
            "package_origin_verified": False
        })
    return {
        "schema_version": "0.1.0",
        "mode": "sbom_inventory",
        "bom_format": "CycloneDX",
        "spec_version": document.get("specVersion"),
        "serial_number": document.get("serialNumber"),
        "components": components,
        "component_count": len(components),
        "limitations": [
            "SBOM provenance, freshness and association with deployed image digest are unverified",
            "No CVE matching or vendor backport evaluation",
            "Component versions alone do not establish vulnerability applicability"
        ]
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("sbom", help="CycloneDX JSON file")
    args = parser.parse_args()
    print(json.dumps(read_sbom(args.sbom), indent=2))

if __name__ == "__main__":
    main()
