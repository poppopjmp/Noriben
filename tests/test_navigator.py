"""
Unit tests for the v3.0.2 MITRE ATT&CK Navigator layer export.

Run with:  python -m unittest discover -s tests -v
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import Noriben  # noqa: E402


def _proc(cmdline):
    return '[CreateProcess] mal.exe:1 > {}\t[Child PID: 2]'.format(cmdline)


def _techniques(cmdlines):
    ind = Noriben.analyze_indicators([_proc(c) for c in cmdlines], [], [], [], [], 'SHA256')
    return Noriben.detect_attack_techniques(ind)


class NavigatorLayerTests(unittest.TestCase):
    def setUp(self):
        self.techniques = _techniques(['whoami', 'vssadmin delete shadows', 'powershell x'])
        self.layer = Noriben.build_navigator_layer(
            self.techniques, {'version': '3.0.2', 'source_csv': 'sample.csv', 'generated': 'now'})

    def test_top_level_shape(self):
        self.assertEqual(self.layer['domain'], 'enterprise-attack')
        self.assertIn('versions', self.layer)
        self.assertEqual(self.layer['versions']['layer'], '4.5')
        self.assertIn('Noriben', self.layer['name'])

    def test_techniques_present_with_ids_and_scores(self):
        ids = {t['techniqueID'] for t in self.layer['techniques']}
        self.assertEqual(ids, {t['id'] for t in self.techniques})
        for entry in self.layer['techniques']:
            self.assertTrue(entry['enabled'])
            self.assertGreaterEqual(entry['score'], 1)
            self.assertIn('tactic', entry)

    def test_gradient_max_at_least_one(self):
        self.assertGreaterEqual(self.layer['gradient']['maxValue'], 1)

    def test_serializable(self):
        text = json.dumps(self.layer)
        self.assertEqual(json.loads(text)['domain'], 'enterprise-attack')

    def test_empty_run(self):
        layer = Noriben.build_navigator_layer([], {'version': '3.0.2'})
        self.assertEqual(layer['techniques'], [])
        self.assertGreaterEqual(layer['gradient']['maxValue'], 1)
        json.dumps(layer)  # must still serialize


if __name__ == '__main__':
    unittest.main()
