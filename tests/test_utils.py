import tempfile
import unittest
from pathlib import Path

from dns_maintenance.utils import normalize_hostname, read_host_file, write_host_file


class UtilsTests(unittest.TestCase):
    def test_normalize_hostname(self):
        self.assertEqual(normalize_hostname(" HTTPS://Example.COM:443/x "), "example.com")

    def test_reject_ip(self):
        self.assertIsNone(normalize_hostname("1.2.3.4"))

    def test_wildcard_normalizes_for_manual_input(self):
        self.assertEqual(normalize_hostname("*.Example.com"), "example.com")

    def test_host_file_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "hosts.txt"
            write_host_file(p, {"b.example.com", "a.example.com"})
            self.assertEqual(read_host_file(p), {"a.example.com", "b.example.com"})
            self.assertEqual(p.read_text(), "a.example.com\nb.example.com\n")
