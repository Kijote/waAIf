"""Correlate Cosign-verified CycloneDX attestations with an SBOM and Docker runtime.

Caller MUST supply output produced by a trusted, successful cosign verify-attestation
invocation. This module does not independently verify signatures or Sigstore identity.
"""
import argparse
import base64
import binascii
import json
import re
from pathlib import Path

HEX = re.compile(r"^[0-9a-f]{64}$")
TYPE = "https://in-toto.io/Statement/v1"
PREDICATE = "https://cyclonedx.org/bom"

def assess(sbom, verified_entries, runtime, project, service, image_digest):
    if not isinstance(image_digest, str) or not HEX.fullmatch(image_digest.removeprefix("sha256:")) or not image_digest.startswith("sha256:"):
        return {"status": "needs_verification", "reason": "Invalid immutable image digest"}
    containers = [s for s in runtime.get("services", []) if s.get("project") == project and s.get("service") == service]
    if len(containers) != 1:
        return {"status": "needs_verification", "reason": "Runtime identity missing or ambiguous"}
    observed = {ref.rsplit("@", 1)[-1] for ref in containers[0].get("repo_digests", []) if isinstance(ref, str) and "@" in ref}
    if not observed:
        return {"status": "needs_verification", "reason": "Runtime repository digest missing"}
    if image_digest not in observed:
        return {"status": "drift_detected", "reason": "Requested image digest differs from runtime observation"}
    if not isinstance(verified_entries, list) or not verified_entries:
        return {"status": "needs_verification", "reason": "No verified attestations supplied"}
    for entry in verified_entries:
        try:
            payload = entry["payload"]
            if isinstance(payload, str):
                payload = json.loads(base64.b64decode(payload, validate=True))
            if not isinstance(payload, dict):
                continue
            if payload.get("_type") != TYPE or payload.get("predicateType") != PREDICATE:
                continue
            subjects = payload.get("subject")
            if not isinstance(subjects, list) or not any(
                isinstance(sub, dict) and isinstance(sub.get("digest"), dict)
                and sub["digest"].get("sha256") == image_digest[7:] for sub in subjects
            ):
                continue
            if payload.get("predicate") != sbom:
                continue
            return {"status": "matched", "cosign_verification_required": True,
                    "reason": "Cosign-verified CycloneDX predicate, image subject and observed runtime digest agree",
                    "limitations": ["Requires trusted Cosign output provenance", "Docker observation is not authenticated", "SBOM completeness and freshness are not proven"]}
        except (KeyError, ValueError, TypeError, binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
            continue
    return {"status": "needs_verification", "reason": "No attestation binds the supplied SBOM to the observed image digest"}

def main():
    p = argparse.ArgumentParser()
    for name in ("sbom", "cosign-output", "runtime", "project", "service", "image-digest"):
        p.add_argument("--" + name, required=True)
    a = p.parse_args()
    for filename, limit in ((a.sbom, 20 * 1024 * 1024), (a.cosign_output, 20 * 1024 * 1024), (a.runtime, 20 * 1024 * 1024)):
        if Path(filename).stat().st_size > limit:
            raise SystemExit("Input exceeds size limit")
    entries = [json.loads(line) for line in Path(a.cosign_output).read_text().splitlines() if line.strip()]
    result = assess(json.loads(Path(a.sbom).read_text()), entries, json.loads(Path(a.runtime).read_text()), a.project, a.service, a.image_digest)
    print(json.dumps({"mode": "cosign_sbom_runtime_correlation", **result}, indent=2))

if __name__ == "__main__":
    main()
