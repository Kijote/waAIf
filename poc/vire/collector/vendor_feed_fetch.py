"""Opt-in, bounded downloader for official public distro security feeds.

Preserves raw bytes with SHA-256 metadata; does not claim normalized advisory states.
"""
import argparse
import hashlib
import json
import os
import re
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SOURCES = {
    "debian": "https://security-tracker.debian.org/tracker/data/json",
    "alpine": "https://secdb.alpinelinux.org/{release}/{repository}.json",
}
MAX_BYTES = 120 * 1024 * 1024

def url_for(distro, *, release=None, repository=None, cve=None):
    if distro == "debian":
        return SOURCES[distro]
    if distro == "alpine":
        if not isinstance(release, str) or not re.fullmatch(r"v3\.\d{1,2}", release):
            raise ValueError("Alpine release must be v3.N")
        if repository not in ("main", "community"):
            raise ValueError("Alpine repository must be main or community")
        return SOURCES[distro].format(release=release, repository=repository)
    if distro == "ubuntu":
        if not isinstance(cve, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
            raise ValueError("Ubuntu CVE must be a valid CVE identifier")
        return SOURCES[distro].format(cve=cve)
    raise ValueError("Unsupported distribution")

def retrieve(url, *, opener=urllib.request.urlopen, max_bytes=MAX_BYTES):
    req = urllib.request.Request(url, headers={"User-Agent": "waAIf-VIRE-PoC/0.1"})
    with opener(req, timeout=60) as response:
        body = response.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise ValueError("Feed exceeds size limit")
    if not body:
        raise ValueError("Empty vendor response")
    return body

def save(output, body, url):
    path = Path(output)
    if path.is_symlink():
        raise ValueError("Refusing symlink output")
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(body).hexdigest()
    metadata = {"schema_version": "0.1.0", "source_url": url,
                "retrieved_at": datetime.now(timezone.utc).isoformat(),
                "sha256": digest, "size_bytes": len(body), "normalization": "none",
                "verified_vendor_status": False}
    for target, data in ((path, body), (Path(str(path) + ".metadata.json"), (json.dumps(metadata, indent=2) + "\n").encode())):
        if target.is_symlink():
            raise ValueError("Refusing symlink output")
        fd, tmp = tempfile.mkstemp(prefix=".vendor-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            os.chmod(tmp, 0o600)
            os.replace(tmp, target)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    return metadata

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--distro", required=True, choices=sorted(SOURCES))
    p.add_argument("--release")
    p.add_argument("--repository")
    p.add_argument("--cve")
    p.add_argument("--output", required=True)
    a = p.parse_args()
    url = url_for(a.distro, release=a.release, repository=a.repository, cve=a.cve)
    meta = save(a.output, retrieve(url), url)
    print(json.dumps(meta, indent=2))

if __name__ == "__main__":
    main()
