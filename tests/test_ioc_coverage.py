"""
Coverage tests ensuring every extracted IOC class flows through the whole
pipeline: single-run report -> JSON -> run-to-run diff -> multi-run merge.

This guards against a category being added to the extractor but forgotten in
the diff/consolidation views (which is exactly how URLs and wallet addresses
were originally missed).

Run with:  python -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import Noriben  # noqa: E402

BTC_A = 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'
BTC_B = '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'


def _report(url, wallet, ip, email):
    procs = ['[CreateProcess] m.exe:1 > cmd /c curl {} and mail {}\t[Child PID: 2]'.format(url, email)]
    reg = ['[RegSetValue] m.exe:1 > HKCU\\Software\\X\\Run\\E  =  pay {} host {}'.format(wallet, ip)]
    ind = Noriben.analyze_indicators(procs, [], reg, [], [], 'SHA256')
    tech = Noriben.detect_attack_techniques(ind)
    return Noriben.build_json_report(ind, tech, {'version': 'x'})


class EnrichedIocsInJsonTests(unittest.TestCase):
    def test_all_classes_reach_the_json_iocs_block(self):
        data = _report('http://a.evil/x', BTC_A, '203.0.113.9', 'a@evil.test')
        iocs = data['iocs']
        self.assertIn('http://a.evil/x', iocs['urls'])
        self.assertIn(BTC_A, iocs['bitcoin'])
        self.assertIn('203.0.113.9', iocs['ipv4'])
        self.assertIn('a@evil.test', iocs['emails'])


class EnrichedIocsInDiffTests(unittest.TestCase):
    def setUp(self):
        self.old = _report('http://old.evil/a', BTC_A, '203.0.113.9', 'old@evil.test')
        self.new = _report('http://new.evil/b', BTC_B, '198.51.100.7', 'new@evil.test')
        self.diff = Noriben.diff_reports(self.old, self.new)

    def test_url_change_is_detected(self):
        self.assertIn('http://new.evil/b', self.diff['urls']['added'])
        self.assertIn('http://old.evil/a', self.diff['urls']['removed'])

    def test_wallet_change_is_detected(self):
        self.assertIn(BTC_B, self.diff['crypto']['added'])
        self.assertIn(BTC_A, self.diff['crypto']['removed'])

    def test_ip_and_email_changes_are_detected(self):
        self.assertIn('198.51.100.7', self.diff['ipv4']['added'])
        self.assertIn('new@evil.test', self.diff['emails']['added'])

    def test_rendered_diff_mentions_the_new_indicators(self):
        blob = '\n'.join(Noriben.format_diff_section(self.diff, 'base.json'))
        self.assertIn('URLs:', blob)
        self.assertIn('http://new.evil/b', blob)
        self.assertIn('Cryptocurrency addresses:', blob)

    def test_html_diff_uses_the_same_categories(self):
        html = Noriben.build_diff_html(self.diff, 'base.json', {'version': '3'})
        self.assertIn('URLs', html)
        self.assertIn('http://new.evil/b', html)

    def test_identical_runs_show_no_enriched_changes(self):
        same = Noriben.diff_reports(self.old, self.old)
        for key in ('urls', 'crypto', 'ipv4', 'emails'):
            self.assertEqual(same[key]['added'], [])
            self.assertEqual(same[key]['removed'], [])


class EnrichedIocsInConsolidationTests(unittest.TestCase):
    def test_shared_url_is_flagged_across_runs(self):
        shared = 'http://shared-c2.evil/beacon'
        runs = [('a.csv', _report(shared, BTC_A, '203.0.113.9', 'a@evil.test')),
                ('b.csv', _report(shared, BTC_B, '198.51.100.7', 'b@evil.test'))]
        consolidated = Noriben.consolidate_reports(runs)

        urls = {e['value']: e for e in consolidated['categories']['urls']}
        self.assertEqual(urls[shared]['count'], 2)

        # Wallets differ per run, so each is seen once
        crypto = {e['value']: e for e in consolidated['categories']['crypto']}
        self.assertEqual(crypto[BTC_A]['count'], 1)
        self.assertEqual(crypto[BTC_B]['count'], 1)

    def test_consolidated_text_lists_enriched_categories(self):
        runs = [('a.csv', _report('http://s.evil/x', BTC_A, '203.0.113.9', 'a@evil.test'))]
        blob = '\n'.join(Noriben.format_consolidated_section(Noriben.consolidate_reports(runs)))
        self.assertIn('URLs', blob)
        self.assertIn('http://s.evil/x', blob)


class DiffCategoryConsistencyTests(unittest.TestCase):
    """The diff data keys and the display labels must stay in sync."""

    def test_labels_cover_every_diff_key(self):
        report = _report('http://a.evil/x', BTC_A, '203.0.113.9', 'a@evil.test')
        diff_keys = set(Noriben.diff_reports(report, report).keys())
        label_keys = {key for key, _label in Noriben._DIFF_CATEGORY_LABELS}
        self.assertEqual(diff_keys, label_keys,
                         'diff_reports() and _DIFF_CATEGORY_LABELS have drifted apart')


if __name__ == '__main__':
    unittest.main()
