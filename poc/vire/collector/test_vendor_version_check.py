import subprocess
import unittest
from unittest.mock import Mock
from vendor_version_check import compare

def runner(returncode, stdout="", stderr=""):
    return Mock(return_value=Mock(returncode=returncode, stdout=stdout, stderr=stderr))

class NativeVersionTests(unittest.TestCase):
    def test_debian_fixed(self):
        self.assertEqual(compare("debian", "1:3.0.17-1~deb12u2", "1:3.0.17-1~deb12u1", runner=runner(0))["status"], "at_or_above_fixed_version")

    def test_debian_below(self):
        self.assertEqual(compare("debian", "3.0.17-1~deb12u1", "3.0.17-1~deb12u2", runner=runner(1))["status"], "below_fixed_version")

    def test_debian_invalid_comparison(self):
        self.assertEqual(compare("debian", "invalid", "fixed", runner=runner(2, stderr="bad"))["status"], "needs_verification")

    def test_alpine_equal(self):
        self.assertEqual(compare("alpine", "3.3.2-r1", "3.3.2-r1", runner=runner(0, "="))["status"], "at_or_above_fixed_version")

    def test_alpine_below(self):
        self.assertEqual(compare("alpine", "3.3.2-r0", "3.3.2-r1", runner=runner(0, "<"))["status"], "below_fixed_version")

    def test_alpine_unknown(self):
        self.assertEqual(compare("alpine", "3.3.2-r1", "3.3.2-r0", runner=runner(0, "?"))["status"], "needs_verification")

    def test_missing_tool(self):
        unavailable = Mock(side_effect=FileNotFoundError())
        self.assertEqual(compare("alpine", "1", "2", runner=unavailable)["status"], "needs_verification")

    def test_reject_invalid_distro(self):
        with self.assertRaises(ValueError):
            compare("ubuntu", "1", "2")

    def test_reject_newline(self):
        with self.assertRaises(ValueError):
            compare("debian", "1\n2", "2")

if __name__ == "__main__":
    unittest.main()
