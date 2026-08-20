import unittest

from dns_maintenance.discovery import extract_candidates, normalize_discovery_state


class DiscoveryTests(unittest.TestCase):
    def test_extract_concrete_names(self):
        page = [{"dns_names": ["telegram.org", "api.telegram.org", "*.telegram.org", "evil.org"]}]
        self.assertEqual(extract_candidates(page, "telegram.org"), {"telegram.org", "api.telegram.org"})

    def test_v1_state_is_accepted(self):
        state = {"version": 1, "sources": {"certspotter": {"telegram.org": {"after": 123}}}}
        result = normalize_discovery_state(state)
        self.assertEqual(result["version"], 2)
        self.assertEqual(result["sources"]["certspotter"]["telegram.org"]["after"], 123)
