import unittest
from vendor_normalize import normalize

CVE = "CVE-2026-12345"

class VendorNormalizeTests(unittest.TestCase):
    def test_debian_release_and_fixed_version(self):
        feed = {"openssl": {CVE: {"releases": {"bookworm": {"status": "resolved", "fixed_version": "3.0.17-1~deb12u1", "urgency": "high"}, "trixie": {"status": "open"}}}}}
        result = normalize(feed, "debian", "bookworm", {CVE})
        self.assertEqual(result["entries"][0]["fixed_version"], "3.0.17-1~deb12u1")
        self.assertEqual(result["entries"][0]["applicability"], "needs_verification")
        self.assertEqual(len(normalize(feed, "debian", "bullseye", {CVE})["entries"]), 0)

    def test_alpine_pkg_secfixes(self):
        feed = {"packages": [{"pkg": {"name": "openssl", "secfixes": {"3.3.2-r1": [CVE, "CVE-2026-99999"]}}}]}
        result = normalize(feed, "alpine", "v3.22", {CVE}, "main")
        self.assertEqual(len(result["entries"]), 1)
        self.assertEqual(result["entries"][0]["fixed_version"], "3.3.2-r1")
        self.assertEqual(result["entries"][0]["repository"], "main")

    def test_no_cve(self):
        self.assertEqual(normalize({"packages": []}, "alpine", "v3.22", {CVE}, "community")["entries"], [])

    def test_reject_bad_schema(self):
        with self.assertRaises(ValueError):
            normalize({"packages": {}}, "alpine", "v3.22", {CVE}, "main")

    def test_ubuntu_pending(self):
        with self.assertRaises(ValueError):
            normalize({}, "ubuntu", "noble", {CVE})

    def test_missing_alpine_repository(self):
        with self.assertRaises(ValueError):
            normalize({"packages": []}, "alpine", "v3.22", {CVE})

if __name__ == "__main__":
    unittest.main()
