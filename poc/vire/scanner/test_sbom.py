import json
import tempfile
import unittest
from pathlib import Path
from sbom import read_sbom

class SbomTests(unittest.TestCase):
    def test_cyclonedx_components(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sbom.json"
            path.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5",
                "components": [{"type": "library", "name": "openssl", "version": "3.0.0", "purl": "pkg:apk/alpine/openssl@3.0.0"},
                               {"type": "library", "name": "unknown"}]}))
            report = read_sbom(path)
            self.assertEqual(report["component_count"], 1)
            self.assertFalse(report["components"][0]["package_origin_verified"])
            self.assertEqual(report["components"][0]["name"], "openssl")

    def test_invalid_format(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sbom.json"
            path.write_text('{"bomFormat":"SPDX","components":[]}')
            with self.assertRaises(ValueError):
                read_sbom(path)

    def test_oversize_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sbom.json"
            path.write_bytes(b"x" * (20 * 1024 * 1024 + 1))
            with self.assertRaises(ValueError):
                read_sbom(path)

if __name__ == "__main__":
    unittest.main()
