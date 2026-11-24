import unittest
from scan import assess

ADVISORY = {"product": "nginx", "affected_from": "1.26.0", "affected_before": "1.28.0", "requires_feature": "http2"}

class AssessTests(unittest.TestCase):
    def test_affected(self):
        self.assertEqual(assess({"product":"nginx","upstream_version":"1.27.0","features":{"http2":True}}, ADVISORY)[0], "affected")
    def test_not_affected_version(self):
        self.assertEqual(assess({"product":"nginx","upstream_version":"1.29.0"}, ADVISORY)[0], "not_affected")
    def test_feature_disabled(self):
        self.assertEqual(assess({"product":"nginx","upstream_version":"1.27.0","features":{"http2":False}}, ADVISORY)[0], "not_affected")
    def test_unknown_feature(self):
        self.assertEqual(assess({"product":"nginx","upstream_version":"1.27.0"}, ADVISORY)[0], "needs_verification")
    def test_backport_requires_reference(self):
        self.assertEqual(assess({"product":"nginx","vendor_fix_status":"fixed"}, ADVISORY)[0], "needs_verification")
    def test_backport_with_reference(self):
        self.assertEqual(assess({"product":"nginx","vendor_fix_status":"fixed","vendor_advisory_reference":"https://vendor.example/advisory"}, ADVISORY)[0], "not_affected")

if __name__ == "__main__":
    unittest.main()
