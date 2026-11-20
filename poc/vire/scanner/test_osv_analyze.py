import unittest
from datetime import datetime, timezone
from osv_analyze import analyze

CACHE = {"source": "osv_querybatch", "retrieved_at": "2026-11-20T12:00:00+00:00",
         "queries": [{"package": {"purl": "pkg:pypi/example"}, "version": "1.0"}],
         "results": [{"vulns": [{"id": "GHSA-demo"}]}]}

class OsvAnalysisTests(unittest.TestCase):
    def test_potential_not_confirmed(self):
        report = analyze(CACHE, now=datetime(2026, 11, 20, 13, tzinfo=timezone.utc))
        self.assertEqual(report["findings"][0]["status"], "potentially_affected")
        self.assertTrue(report["findings"][0]["requires_vendor_backport_review"])
        self.assertTrue(report["cache_fresh"])

    def test_stale_cache(self):
        report = analyze(CACHE, now=datetime(2026, 12, 20, tzinfo=timezone.utc))
        self.assertFalse(report["cache_fresh"])

    def test_bad_alignment(self):
        with self.assertRaises(ValueError):
            analyze({**CACHE, "results": []})

    def test_bad_source(self):
        with self.assertRaises(ValueError):
            analyze({**CACHE, "source": "unknown"})

if __name__ == "__main__":
    unittest.main()
