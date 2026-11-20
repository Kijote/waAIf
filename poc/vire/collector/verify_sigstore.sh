#!/usr/bin/env bash
# Host-side keyless Sigstore verification using the official cosign CLI.
# Fail closed: do not claim success without cosign verification and an identity policy.
set -euo pipefail
: "${IMAGE_DIGEST:?Set immutable IMAGE_DIGEST (registry/repository@sha256:...)}"
: "${CERT_IDENTITY:?Set exact trusted certificate identity}"
: "${CERT_OIDC_ISSUER:?Set exact trusted OIDC issuer}"
: "${OUTPUT:?Set path for verified attestation JSON}"
if [[ ! "$IMAGE_DIGEST" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]]; then
  echo "IMAGE_DIGEST must be a registry image reference with immutable sha256 digest" >&2
  exit 2
fi
if ! command -v cosign >/dev/null 2>&1; then
  echo "cosign CLI is required on the trusted host" >&2
  exit 2
fi
umask 077
outdir="$(dirname "$OUTPUT")"
mkdir -p "$outdir"
tmp="$(mktemp "$outdir/.sigstore-verify.XXXXXXXX")"
trap 'rm -f "$tmp"' EXIT
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity "$CERT_IDENTITY" \
  --certificate-oidc-issuer "$CERT_OIDC_ISSUER" \
  "$IMAGE_DIGEST" > "$tmp"
python3 - "$tmp" <<'PY'
import json, sys
from pathlib import Path
data = Path(sys.argv[1]).read_text()
for line in data.splitlines():
    if not line.strip():
        continue
    entry = json.loads(line)
    if not isinstance(entry, dict):
        raise SystemExit("Unexpected cosign output shape")
    payload = entry.get("payload")
    if payload is not None and not isinstance(payload, dict):
        raise SystemExit("Unexpected payload shape")
if not data.strip():
    raise SystemExit("cosign returned no verified attestations")
PY
mv "$tmp" "$OUTPUT"
trap - EXIT
echo "Verified Cosign output saved to $OUTPUT" >&2
