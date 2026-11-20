"""Trusted host-side Cosign verification and immediate VIRE correlation.

Does not accept a pre-verified JSONL path; runs Cosign itself with exact identity policy.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scanner"))
from cosign_binding import assess

IMAGE_RE = re.compile(r"^[^\s@]+@sha256:([0-9a-f]{64})$")

def run(image, identity, issuer, sbom, runtime, project, service, *, runner=subprocess.run):
    match = IMAGE_RE.fullmatch(image)
    if not match:
        raise ValueError("Image must use an immutable sha256 digest")
    if not identity or not issuer or any(c in identity + issuer for c in "\r\n\x00"):
        raise ValueError("Exact certificate identity and issuer are required")
    cmd = ["cosign", "verify-attestation", "--type", "cyclonedx",
           "--certificate-identity", identity, "--certificate-oidc-issuer", issuer, image]
    try:
        result = runner(cmd, capture_output=True, text=True, check=True, timeout=120)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return {"status": "needs_verification", "reason": "Cosign verification failed or was unavailable", "cosign_verified": False}
    try:
        entries = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        if not entries:
            raise ValueError("No attestations")
        report = assess(sbom, entries, runtime, project, service, "sha256:" + match.group(1))
        return {"cosign_verified": True, **report}
    except (ValueError, TypeError, json.JSONDecodeError):
        return {"status": "needs_verification", "reason": "Invalid Cosign output", "cosign_verified": False}

def main():
    p = argparse.ArgumentParser()
    for name in ("image", "identity", "issuer", "sbom", "runtime", "project", "service"):
        p.add_argument("--" + name, required=True)
    a = p.parse_args()
    for path in (a.sbom, a.runtime):
        if Path(path).stat().st_size > 20 * 1024 * 1024:
            raise SystemExit("Input too large")
    report = run(a.image, a.identity, a.issuer, json.loads(Path(a.sbom).read_text()),
                 json.loads(Path(a.runtime).read_text()), a.project, a.service)
    print(json.dumps({"mode": "trusted_cosign_runtime_binding", **report}, indent=2))
    if report["status"] != "matched":
        raise SystemExit(1)

if __name__ == "__main__":
    main()
