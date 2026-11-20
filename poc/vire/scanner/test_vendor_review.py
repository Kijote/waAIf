import unittest
from vendor_review import review

OSV = {"mode": "offline_osv_candidates", "findings": [
    {"id": "CVE-2026-0001", "package": {"purl": "pkg:deb/debian/openssl"}, "version": "3.0"}]}
PKG = {"purl": "pkg:deb/debian/openssl", "version": "3.0", "distro": "debian",
       "distro_release": "bookworm", "source_package": "openssl", "installed_version": "3.0.17-1~deb12u1"}
INV = {"packages": [PKG]}
ENTRY = {"distro": "debian", "distro_release": "bookworm", "source_package": "openssl",
         "installed_version": "3.0.17-1~deb12u1", "vulnerability_id": "CVE-2026-0001",
         "state": "fixed", "advisory_url": "https://security-tracker.debian.org/"}
ADV = {"source": "normalized_vendor_advisories", "entries": [ENTRY]}

class VendorReviewTests(unittest.TestCase):
    def test_exact_vendor_fixed(self):
        self.assertEqual(review(OSV, INV, ADV)["findings"][0]["status"], "vendor_fixed")

    def test_vendor_affected(self):
        self.assertEqual(review(OSV, INV, {**ADV, "entries": [{**ENTRY, "state": "affected"}]})["findings"][0]["status"], "vendor_affected")

    def test_no_advisory(self):
        self.assertEqual(review(OSV, INV, {**ADV, "entries": []})["findings"][0]["status"], "needs_verification")

    def test_wrong_installed_revision(self):
        self.assertEqual(review(OSV, INV, {**ADV, "entries": [{**ENTRY, "installed_version": "3.0.17-1~deb12u2"}]})["findings"][0]["status"], "needs_verification")

    def test_ambiguous_advisories(self):
        self.assertEqual(review(OSV, INV, {**ADV, "entries": [ENTRY, ENTRY]})["findings"][0]["status"], "needs_verification")

    def test_missing_distro(self):
        self.assertEqual(review(OSV, {"packages": [{**PKG, "distro": None}]}, ADV)["findings"][0]["status"], "needs_verification")

    def test_ubuntu_and_alpine_supported(self):
        for distro in ("ubuntu", "alpine"):
            pkg = {**PKG, "distro": distro}
            entry = {**ENTRY, "distro": distro, "state": "not_affected"}
            self.assertEqual(review(OSV, {"packages": [pkg]}, {**ADV, "entries": [entry]})["findings"][0]["status"], "vendor_not_affected")

if __name__ == "__main__":
    unittest.main()
