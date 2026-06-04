"""
Unit tests for the v2.5.0 consolidated multi-run analysis (--merge).

Run with:  python -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import Noriben  # noqa: E402


def _report(name, files, hosts):
    ind = Noriben.analyze_indicators([], files, [], [], hosts, 'SHA256')
    report = Noriben.build_json_report(ind, Noriben.detect_attack_techniques(ind), {'version': 'x'})
    return name, report


# run A and B share evil.com and a.exe; each has a unique host
RUN_A = _report('a.csv',
                ['[CreateFile] m.exe:1 > C:\\a.exe\t[SHA256: {}]'.format('a' * 64)],
                ['evil.com', 'only-a.com'])
RUN_B = _report('b.csv',
                ['[CreateFile] m.exe:1 > C:\\a.exe\t[SHA256: {}]'.format('a' * 64)],
                ['evil.com', 'only-b.com'])


class ConsolidateTests(unittest.TestCase):
    def setUp(self):
        self.con = Noriben.consolidate_reports([RUN_A, RUN_B])

    def test_run_names_and_count(self):
        self.assertEqual(self.con['run_count'], 2)
        self.assertEqual(self.con['runs'], ['a.csv', 'b.csv'])

    def test_shared_host_counted_in_both(self):
        hosts = {e['value']: e for e in self.con['categories']['network_hosts']}
        self.assertEqual(hosts['evil.com']['count'], 2)
        self.assertEqual(hosts['evil.com']['runs'], ['a.csv', 'b.csv'])
        self.assertEqual(hosts['only-a.com']['count'], 1)

    def test_shared_first_in_ordering(self):
        # evil.com (count 2) should sort ahead of the count-1 hosts
        self.assertEqual(self.con['categories']['network_hosts'][0]['value'], 'evil.com')

    def test_shared_file(self):
        files = {e['value']: e for e in self.con['categories']['files_created']}
        self.assertEqual(files['C:\\a.exe']['count'], 2)


class FormatAndHtmlTests(unittest.TestCase):
    def test_text_section_marks_shared(self):
        con = Noriben.consolidate_reports([RUN_A, RUN_B])
        blob = '\n'.join(Noriben.format_consolidated_section(con))
        self.assertIn('Consolidated Multi-Run Report (2 runs)', blob)
        self.assertIn('[SHARED]', blob)
        self.assertIn('evil.com', blob)

    def test_html_is_escaped_and_structured(self):
        con = Noriben.consolidate_reports([
            _report('x.csv', ['[CreateFile] m.exe:1 > C:\\a&<b.exe\t[SHA256: {}]'.format('a' * 64)], ['h.com'])])
        html = Noriben.build_consolidated_html(con, {'version': '2.5.0', 'generated': 'now'})
        self.assertIn('<!DOCTYPE html>', html)
        self.assertIn('consolidated multi-run report', html)
        self.assertIn('&amp;', html)
        self.assertIn('&lt;', html)


class RunConsolidationTests(unittest.TestCase):
    def test_end_to_end_writes_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            # write two iocs.json files
            for name, report in (RUN_A, RUN_B):
                with open(os.path.join(tmp, name.replace('.csv', '.iocs.json')), 'w', encoding='utf-8') as handle:
                    json.dump(report, handle)
            config = {'output_folder': tmp, 'troubleshoot': False}
            Noriben.run_consolidation([tmp], config)  # pass the directory
            for ext in ('txt', 'json', 'html'):
                self.assertTrue(os.path.exists(os.path.join(tmp, 'Noriben_consolidated.' + ext)))
            with open(os.path.join(tmp, 'Noriben_consolidated.json'), encoding='utf-8') as handle:
                data = json.load(handle)
            self.assertEqual(data['run_count'], 2)

    def test_no_reports_is_graceful(self):
        with tempfile.TemporaryDirectory() as tmp:
            # should not raise even with nothing to merge
            Noriben.run_consolidation([os.path.join(tmp, 'nope.iocs.json')], {'output_folder': tmp})


if __name__ == '__main__':
    unittest.main()
