"""Verify an SBOM's claimed image digest against observed Docker repository digests.

A matching claim is necessary but not sufficient: provenance remains unverified.
"""
import argparse
import json
import re
from pathlib import Path

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")

def check(sbom, runtime, binding):
    claimed = binding.get("image_digest")
    service = binding.get("service")
    project = binding.get("project")
    if not isinstance(claimed, str) or not DIGEST.fullmatch(claimed):
        return {"status": "needs_verification", "reason": "Invalid or absent immutable image digest"}
    matches = [s for s in runtime.get("services", []) if s.get("service") == service and s.get("project") == project]
    if len(matches) != 1:
        return {"status": "needs_verification", "reason": "Service identity is missing or ambiguous"}
    observation = matches[0]
    observed = {ref.rsplit("@", 1)[-1] for ref in observation.get("repo_digests", []) if isinstance(ref, str) and "@" in ref}
    if not observed:
        return {"status": "needs_verification", "reason": "No runtime registry digest evidence"}
    if claimed not in observed:
        return {"status": "drift_detected", "reason": "Claimed SBOM image digest differs from runtime repository digests"}
    if sbom.get("mode") != "sbom_inventory" or not sbom.get("components"):
        return {"status": "needs_verification", "reason": "Missing normalized SBOM components"}
    return {"status": "needs_verification", "reason": "Image digest agrees, but SBOM provenance and binding authenticity are unverified",
            "digest_consistent": True}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("sbom")
    parser.add_argument("runtime")
    parser.add_argument("binding")
    args = parser.parse_args()
    report = check(json.loads(Path(args.sbom).read_text()), json.loads(Path(args.runtime).read_text()), json.loads(Path(args.binding).read_text()))
    print(json.dumps({"mode": "sbom_runtime_binding", **report}, indent=2))

if __name__ == "__main__":
    main()
