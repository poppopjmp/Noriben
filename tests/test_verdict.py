"""
Unit tests for the v3.0.0 analytics:
  * deterministic verdict / risk-scoring engine
  * process tree reconstruction
  * single-run HTML dashboard

Run with:  python -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import Noriben  # noqa: E402

SHA = 'f' * 64

MALICIOUS_FILES = [
    '[CreateFile] m.exe:1 > C:\\Users\\v\\AppData\\Roaming\\evil.exe\t[SHA256: {}]'.format(SHA),
    '[DeleteFile] m.exe:1 > C:\\Users\\v\\dropper.exe',
]
MALICIOUS_REG = [
    '[RegSetValue] m.exe:1 > HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil  =  C:\\evil.exe',
]
MALICIOUS_PROC = [
    '[CreateProcess] m.exe:1 > vssadmin delete shadows /all /quiet\t[Child PID: 2]',
    '[CreateProcess] m.exe:1 > powershell.exe -enc QQBBAEEAQQBCAGMA\t[Child PID: 3]',
]


def _mal_indicators():
    return Noriben.analyze_indicators(MALICIOUS_PROC, MALICIOUS_FILES, MALICIOUS_REG,
                                      [], ['evil.com'], 'SHA256')


class ScoreSampleTests(unittest.TestCase):
    def test_malicious_verdict(self):
        ind = _mal_indicators()
        verdict = Noriben.score_sample(ind, Noriben.detect_attack_techniques(ind))
        self.assertEqual(verdict['verdict'], 'Malicious')
        self.assertGreaterEqual(verdict['score'], 60)
        self.assertEqual(verdict['confidence'], 'High')
        self.assertTrue(any('recovery' in r.lower() for r in verdict['reasons']))
        self.assertTrue(any('persistence' in r.lower() for r in verdict['reasons']))

    def test_score_capped_at_100(self):
        ind = _mal_indicators()
        verdict = Noriben.score_sample(ind, Noriben.detect_attack_techniques(ind))
        self.assertLessEqual(verdict['score'], 100)

    def test_benign_verdict(self):
        ind = Noriben.analyze_indicators(
            ['[CreateProcess] notepad.exe:1 > notepad.exe readme.txt\t[Child PID: 2]'],
            [], [], [], [], 'SHA256')
        verdict = Noriben.score_sample(ind, Noriben.detect_attack_techniques(ind))
        self.assertEqual(verdict['verdict'], 'Likely Benign / Inconclusive')
        self.assertEqual(verdict['score'], 0)
        self.assertTrue(verdict['reasons'])

    def test_suspicious_middle_band(self):
        # A single dropped exe + one host: notable but not clearly malicious
        ind = Noriben.analyze_indicators(
            [], ['[CreateFile] m.exe:1 > C:\\x\\a.exe\t[SHA256: {}]'.format(SHA)], [], [],
            ['some.host'], 'SHA256')
        verdict = Noriben.score_sample(ind, Noriben.detect_attack_techniques(ind))
        self.assertIn(verdict['verdict'], ('Suspicious', 'Likely Benign / Inconclusive'))
        self.assertLess(verdict['score'], 60)


class ProcessTreeTests(unittest.TestCase):
    def test_tree_links_parent_and_child(self):
        procs = [
            {'process': 'explorer.exe', 'pid': '100', 'command_line': 'malware.exe', 'child_pid': '200'},
            {'process': 'malware.exe', 'pid': '200', 'command_line': 'cmd /c whoami', 'child_pid': '300'},
        ]
        roots = Noriben.build_process_tree(procs)
        self.assertEqual(len(roots), 1)
        self.assertEqual(roots[0]['pid'], '100')
        self.assertEqual(roots[0]['children'][0]['pid'], '200')
        self.assertEqual(roots[0]['children'][0]['children'][0]['pid'], '300')

    def test_format_tree_indents(self):
        procs = [{'process': 'a.exe', 'pid': '1', 'command_line': 'b.exe', 'child_pid': '2'}]
        lines = Noriben.format_process_tree(Noriben.build_process_tree(procs))
        self.assertTrue(lines[0].startswith('[1]'))
        self.assertTrue(any(line.startswith('    [2]') for line in lines))

    def test_cycle_is_handled(self):
        procs = [
            {'process': 'a', 'pid': '1', 'command_line': 'b', 'child_pid': '2'},
            {'process': 'b', 'pid': '2', 'command_line': 'a', 'child_pid': '1'},
        ]
        # Must not infinite-loop
        lines = Noriben.format_process_tree(Noriben.build_process_tree(procs))
        self.assertTrue(any('cycle' in line for line in lines))


class VerdictSectionTests(unittest.TestCase):
    def test_section_has_banner(self):
        ind = _mal_indicators()
        verdict = Noriben.score_sample(ind, Noriben.detect_attack_techniques(ind))
        blob = '\n'.join(Noriben.format_verdict_section(verdict))
        self.assertIn('VERDICT: Malicious', blob)
        self.assertIn('risk score', blob)
        self.assertIn('Why:', blob)


class RunHtmlTests(unittest.TestCase):
    def _report(self):
        ind = _mal_indicators()
        tech = Noriben.detect_attack_techniques(ind)
        verdict = Noriben.score_sample(ind, tech)
        tree = Noriben.build_process_tree(ind['processes'])
        return Noriben.build_json_report(ind, tech, {'version': '3.0.0', 'source_csv': 'x.csv'},
                                         verdict=verdict, process_tree=tree)

    def test_html_contains_verdict_and_sections(self):
        html = Noriben.build_run_html(self._report(), {'version': '3.0.0', 'generated': 'now',
                                                       'source_csv': 'x.csv'})
        self.assertIn('<!DOCTYPE html>', html)
        self.assertIn('Noriben analysis report', html)
        self.assertIn('Malicious', html)
        self.assertIn('MITRE ATT&amp;CK techniques', html)
        self.assertIn('Process tree', html)
        self.assertIn(SHA, html)
        self.assertIn('evil.com', html)

    def test_html_escapes_payload(self):
        ind = Noriben.analyze_indicators(
            [], ['[CreateFile] m.exe:1 > C:\\a&<b.exe\t[SHA256: {}]'.format(SHA)], [], [], [], 'SHA256')
        data = Noriben.build_json_report(ind, [], {'version': '3.0.0'},
                                         verdict=Noriben.score_sample(ind, []),
                                         process_tree=[])
        html = Noriben.build_run_html(data, {'version': '3.0.0'})
        self.assertIn('&amp;', html)
        self.assertIn('&lt;', html)


class JsonReportVerdictTests(unittest.TestCase):
    def test_json_includes_verdict_and_tree(self):
        ind = _mal_indicators()
        tech = Noriben.detect_attack_techniques(ind)
        data = Noriben.build_json_report(ind, tech, {'version': '3.0.0'},
                                         verdict=Noriben.score_sample(ind, tech),
                                         process_tree=Noriben.build_process_tree(ind['processes']))
        self.assertEqual(data['verdict']['verdict'], 'Malicious')
        self.assertIsInstance(data['process_tree'], list)

    def test_backwards_compatible_without_verdict(self):
        # Older callers that omit verdict/tree still work
        ind = Noriben.analyze_indicators([], [], [], [], [], 'SHA256')
        data = Noriben.build_json_report(ind, [], {'version': '3.0.0'})
        self.assertIsNone(data['verdict'])
        self.assertEqual(data['process_tree'], [])


if __name__ == '__main__':
    unittest.main()
