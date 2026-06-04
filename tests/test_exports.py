"""
Unit tests for the v2.3.0 reverse-engineering exports:
  * named pipe / mutex extraction
  * suggested YARA rule generation
  * run-to-run diff
  * STIX 2.1 and MISP IOC exports

Run with:  python -m unittest discover -s tests -v
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import Noriben  # noqa: E402

SHA = 'b' * 64

FILE_OUTPUT = [
    '[CreateFile] malware.exe:1234 > C:\\Users\\v\\AppData\\Roaming\\evil.exe\t[SHA256: {}]'.format(SHA),
    '[CreateFile] malware.exe:1234 > \\Device\\NamedPipe\\evilpipe',
    '[CreateFile] malware.exe:1234 > \\BaseNamedObjects\\Global\\EvilMutex',
]
REG_OUTPUT = [
    '[RegSetValue] malware.exe:1234 > HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil  =  C:\\evil.exe',
]
REMOTE_SERVERS = ['1.2.3.4', 'evil.com']


def _indicators():
    return Noriben.analyze_indicators([], FILE_OUTPUT, REG_OUTPUT, [], REMOTE_SERVERS, 'SHA256')


class PipeMutexExtractionTests(unittest.TestCase):
    def test_named_pipe_extracted(self):
        ind = _indicators()
        self.assertIn('evilpipe', ind['named_pipes'])

    def test_mutex_extracted(self):
        ind = _indicators()
        # Full name including the Global namespace is captured
        self.assertEqual(ind['mutexes'], ['Global\\EvilMutex'])

    def test_pipe_mutex_not_counted_as_files(self):
        ind = _indicators()
        paths = [f['path'] for f in ind['files_created']]
        self.assertTrue(any('evil.exe' in p for p in paths))
        self.assertFalse(any('NamedPipe' in p for p in paths))
        self.assertFalse(any('BaseNamedObjects' in p for p in paths))


class YaraRuleTests(unittest.TestCase):
    def test_rule_contains_indicators(self):
        rule = Noriben.build_yara_rule(_indicators(), rule_name='Test Rule', hash_type='SHA256')
        self.assertIn('rule Test_Rule', rule)          # name sanitized
        self.assertIn('condition:', rule)
        self.assertIn('any of them', rule)
        self.assertIn('evil.exe', rule)
        self.assertIn('evil.com', rule)
        self.assertIn(SHA, rule)                       # hash recorded in meta

    def test_empty_indicators_yield_no_rule(self):
        empty = Noriben.analyze_indicators([], [], [], [], [], 'SHA256')
        self.assertEqual(Noriben.build_yara_rule(empty), '')


class DiffTests(unittest.TestCase):
    def _report(self, file_output, remote):
        ind = Noriben.analyze_indicators([], file_output, [], [], remote, 'SHA256')
        tech = Noriben.detect_attack_techniques(ind)
        return Noriben.build_json_report(ind, tech, {'version': 'x'})

    def test_added_and_removed_detected(self):
        old = self._report(['[CreateFile] m.exe:1 > C:\\a.exe\t[SHA256: {}]'.format('a' * 64)], ['old.com'])
        new = self._report(['[CreateFile] m.exe:1 > C:\\b.exe\t[SHA256: {}]'.format('c' * 64)], ['new.com'])
        diff = Noriben.diff_reports(old, new)
        self.assertIn('C:\\b.exe', diff['files_created']['added'])
        self.assertIn('C:\\a.exe', diff['files_created']['removed'])
        self.assertIn('new.com', diff['network_hosts']['added'])
        self.assertIn('old.com', diff['network_hosts']['removed'])

    def test_identical_runs_have_no_diff(self):
        rep = self._report(['[CreateFile] m.exe:1 > C:\\a.exe\t[SHA256: {}]'.format('a' * 64)], ['x.com'])
        diff = Noriben.diff_reports(rep, rep)
        for category in diff.values():
            self.assertEqual(category['added'], [])
            self.assertEqual(category['removed'], [])

    def test_format_diff_section(self):
        old = self._report([], [])
        new = self._report(['[CreateFile] m.exe:1 > C:\\b.exe\t[SHA256: {}]'.format('c' * 64)], ['new.com'])
        lines = Noriben.format_diff_section(Noriben.diff_reports(old, new), 'base.iocs.json')
        blob = '\n'.join(lines)
        self.assertIn('Run-to-Run Diff', blob)
        self.assertIn('[+] C:\\b.exe', blob)


class StixExportTests(unittest.TestCase):
    def test_bundle_structure(self):
        bundle = Noriben.build_stix_bundle(_indicators(), {'generated': '2026-06-04T00:00:00'})
        self.assertEqual(bundle['type'], 'bundle')
        self.assertTrue(bundle['id'].startswith('bundle--'))
        patterns = [o['pattern'] for o in bundle['objects']]
        self.assertTrue(any("file:hashes.'SHA-256' = '{}'".format(SHA) in p for p in patterns))
        self.assertTrue(any("domain-name:value = 'evil.com'" in p for p in patterns))
        self.assertTrue(any("ipv4-addr:value = '1.2.3.4'" in p for p in patterns))
        self.assertTrue(any("mutex:name" in p for p in patterns))
        for obj in bundle['objects']:
            self.assertEqual(obj['type'], 'indicator')
            self.assertEqual(obj['spec_version'], '2.1')
        json.dumps(bundle)  # must serialize

    def test_empty_bundle(self):
        empty = Noriben.analyze_indicators([], [], [], [], [], 'SHA256')
        bundle = Noriben.build_stix_bundle(empty, {})
        self.assertEqual(bundle['objects'], [])


class MispExportTests(unittest.TestCase):
    def test_event_attributes(self):
        event = Noriben.build_misp_event(_indicators(), {'generated': '2026-06-04T00:00:00', 'command_line': 'evil.exe'})
        attrs = event['Event']['Attribute']
        types = {a['type'] for a in attrs}
        values = {a['value'] for a in attrs}
        self.assertIn('sha256', types)
        self.assertIn('domain', types)
        self.assertIn('ip-dst', types)
        self.assertIn('regkey', types)
        self.assertIn('mutex', types)
        self.assertIn(SHA, values)
        self.assertEqual(event['Event']['date'], '2026-06-04')
        json.dumps(event)  # must serialize


if __name__ == '__main__':
    unittest.main()
