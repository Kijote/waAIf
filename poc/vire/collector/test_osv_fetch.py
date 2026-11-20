import json
import unittest
from unittest.mock import Mock
from osv_fetch import API, build_queries, fetch

SBOM = {"components": [
    {"purl": "pkg:pypi/example", "version": "1.0"},
    {"purl": "pkg:pypi/example", "version": "1.0"},
    {"purl": "not-a-purl", "version": "1.0"}]}

class Response:
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self, size):
        return json.dumps({"results": [{"vulns": [{"id": "GHSA-demo"}]}]}).encode()

class OsvFetchTests(unittest.TestCase):
    def test_deduplicate_and_skip_invalid(self):
        self.assertEqual(len(build_queries(SBOM)), 1)

    def test_free_public_endpoint_and_aligned_response(self):
        opener = Mock(return_value=Response())
        report = fetch(SBOM, opener=opener)
        self.assertEqual(len(report["results"]), 1)
        self.assertEqual(opener.call_args.args[0].full_url, API)

    def test_batch_limit(self):
        sbom = {"components": [{"purl": f"pkg:pypi/package{i}", "version": "1"} for i in range(101)]}
        with self.assertRaises(ValueError):
            build_queries(sbom)

    def test_no_network_without_purls(self):
        opener = Mock()
        report = fetch({"components": []}, opener=opener)
        self.assertEqual(report["results"], [])
        opener.assert_not_called()

if __name__ == "__main__":
    unittest.main()
