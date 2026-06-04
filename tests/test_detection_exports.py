"""
Unit tests for the v2.4.0 detection-engineering exports:
  * Sigma rule generation + minimal YAML emitter
  * enhanced YARA strings (registry autostart value names)
  * HTML run-to-run diff report

Run with:  python -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import Noriben  # noqa: E402

SHA = 'd' * 64

PROCESS_OUTPUT = [
    '[CreateProcess] m.exe:1 > powershell.exe -enc QQBBAEEAQQBCAGMAZAo=\t[Child PID: 2]',
]
FILE_OUTPUT = [
    '[CreateFile] m.exe:1 > C:\\Users\\v\\AppData\\Roaming\\evil.exe\t[SHA256: {}]'.format(SHA),
    '[CreateFile] m.exe:1 > \\Device\\NamedPipe\\evilpipe',
]
REG_OUTPUT = [
    '[RegSetValue] m.exe:1 > HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil  =  C:\\evil.exe',
]
REMOTE_SERVERS = ['1.2.3.4', 'evil.com']


def _indicators():
    return Noriben.analyze_indicators(PROCESS_OUTPUT, FILE_OUTPUT, REG_OUTPUT, [], REMOTE_SERVERS, 'SHA256')


class SigmaRuleTests(unittest.TestCase):
    def setUp(self):
        self.ind = _indicators()
        self.tech = Noriben.detect_attack_techniques(self.ind)
        self.rules = Noriben.build_sigma_rules(self.ind, self.tech, {'generated': '2026-06-04T00:00:00'})
        self.titles = {r['title'] for r in self.rules}

    def test_rules_generated_for_each_category(self):
        self.assertIn('Noriben - Dropped Executable Created', self.titles)
        self.assertIn('Noriben - Registry Persistence Modification', self.titles)
        self.assertIn('Noriben - Network Connection to Observed Host', self.titles)
        self.assertIn('Noriben - Named Pipe Created', self.titles)
        self.assertIn('Noriben - Suspicious Process Command Line', self.titles)

    def test_rules_have_required_fields(self):
        for rule in self.rules:
            for field in ('title', 'id', 'logsource', 'detection', 'level', 'tags'):
                self.assertIn(field, rule)
            self.assertEqual(rule['detection']['condition'], 'selection')
            self.assertTrue(rule['logsource']['product'] == 'windows')

    def test_network_rule_splits_ip_and_domain(self):
        net = next(r for r in self.rules if r['title'].endswith('Observed Host'))
        sel = net['detection']['selection']
        self.assertIn('evil.com', sel.get('DestinationHostname', []))
        self.assertIn('1.2.3.4', sel.get('DestinationIp', []))

    def test_persistence_rule_has_attack_tag(self):
        reg = next(r for r in self.rules if 'Persistence' in r['title'])
        self.assertTrue(any(t.startswith('attack.t1547') for t in reg['tags']))

    def test_empty_run_yields_no_rules(self):
        empty = Noriben.analyze_indicators([], [], [], [], [], 'SHA256')
        self.assertEqual(Noriben.build_sigma_rules(empty, [], {}), [])


class SigmaYamlTests(unittest.TestCase):
    def test_yaml_is_valid_and_multidoc(self):
        ind = _indicators()
        rules = Noriben.build_sigma_rules(ind, Noriben.detect_attack_techniques(ind), {})
        yaml_text = Noriben.sigma_rules_to_yaml(rules)
        self.assertIn('title:', yaml_text)
        self.assertIn('\n---\n', yaml_text)            # multiple documents
        self.assertIn('logsource:', yaml_text)
        self.assertIn('detection:', yaml_text)
        self.assertIn('condition: ', yaml_text)

    def test_yaml_parses_with_pyyaml_if_available(self):
        try:
            import yaml
        except ImportError:
            self.skipTest('PyYAML not installed')
        ind = _indicators()
        rules = Noriben.build_sigma_rules(ind, Noriben.detect_attack_techniques(ind), {})
        parsed = list(yaml.safe_load_all(Noriben.sigma_rules_to_yaml(rules)))
        self.assertEqual(len(parsed), len(rules))
        for doc in parsed:
            self.assertIn('detection', doc)
            self.assertEqual(doc['detection']['condition'], 'selection')

    def test_scalar_quote_escaping(self):
        self.assertEqual(Noriben._yaml_scalar("it's"), "'it''s'")
        self.assertEqual(Noriben._yaml_scalar(5), '5')


class YaraRegistryStringTests(unittest.TestCase):
    def test_autostart_value_name_included(self):
        rule = Noriben.build_yara_rule(_indicators())
        self.assertIn('$reg0', rule)
        self.assertIn('Evil', rule)   # the Run value name


class DiffHtmlTests(unittest.TestCase):
    def _report(self, files, remote):
        ind = Noriben.analyze_indicators([], files, [], [], remote, 'SHA256')
        return Noriben.build_json_report(ind, Noriben.detect_attack_techniques(ind), {'version': 'x'})

    def test_html_contains_changes_and_escapes(self):
        old = self._report([], [])
        new = self._report(['[CreateFile] m.exe:1 > C:\\a&b<.exe\t[SHA256: {}]'.format('e' * 64)], ['x.com'])
        diff = Noriben.diff_reports(old, new)
        html = Noriben.build_diff_html(diff, 'base.iocs.json', {'version': '2.4.0', 'generated': 'now'})
        self.assertIn('<!DOCTYPE html>', html)
        self.assertIn('Noriben run-to-run diff', html)
        self.assertIn('x.com', html)
        self.assertIn('&amp;', html)   # & escaped
        self.assertIn('&lt;', html)    # < escaped
        self.assertNotIn('<.exe', html)

    def test_no_changes_message(self):
        rep = self._report([], [])
        html = Noriben.build_diff_html(Noriben.diff_reports(rep, rep), 'base', {})
        self.assertIn('No differences from baseline', html)


if __name__ == '__main__':
    unittest.main()
