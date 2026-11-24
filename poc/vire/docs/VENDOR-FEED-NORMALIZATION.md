# Debian and Alpine vendor feed fact normalization

`scanner/vendor_normalize.py` extracts **facts**, not vulnerability verdicts, from official Debian Security Tracker and Alpine SecDB JSON snapshots. No network access, subscriptions, API keys or cloud account are needed after an opt-in feed download.

## Commands

```sh
cd poc/vire
python3 collector/vendor_feed_fetch.py --distro debian --output reports/debian.json
python3 scanner/vendor_normalize.py --feed reports/debian.json --metadata reports/debian.json.metadata.json --distro debian --release bookworm --cve CVE-2026-12345

python3 collector/vendor_feed_fetch.py --distro alpine --release v3.22 --repository main --output reports/alpine.json
python3 scanner/vendor_normalize.py --feed reports/alpine.json --metadata reports/alpine.json.metadata.json --distro alpine --release v3.22 --repository main --cve CVE-2026-12345
```

CVE identifiers above are illustrative; a nonexistent CVE produces an empty result. The parser validates raw feed SHA-256 against the downloader metadata. **This does not authenticate the vendor**: metadata and feed could both be tampered with, and HTTPS/trusted host remain part of the trust boundary.

## Mapping

- Debian: `source_package -> CVE -> releases -> release -> status/fixed_version/urgency`.
- Alpine: `packages[] -> pkg.name/pkg.secfixes -> fixed_version -> vulnerability identifiers`.

Every entry is marked `applicability: needs_verification`. Debian `resolved` does not establish that the observed installed package is patched; Alpine `secfixes` is a fixed-version reference, not proof of installed-version ordering.

## Outstanding work

- Connect normalized facts to a trusted installed-package inventory.
- Implement distribution-native version comparison (Debian dpkg, Alpine apk), including epochs, revisions, and backports.
- Validate real live feed schema samples and implement parser compatibility tests.
- Add Ubuntu official feed adapter after confirming the canonical supported source.
- Ensure provider source URLs and release identifiers in metadata match the requested distribution.
- Do not feed this output directly to `vendor_review.py`: it intentionally uses a different schema requiring exact installed-release evidence.

No automated mitigation is permitted based on this output.
