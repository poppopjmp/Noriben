"""
Regression tests for engine robustness and the approvelist filter cache.

Covers:
  * approvelist_scan semantics are preserved by the memoized filter compiler
    (including invalid-regex filters), and the cache is actually used
  * a failing exporter never costs the analyst the primary text report

Run with:  python -m unittest discover -s tests -v
"""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import Noriben  # noqa: E402


def _legacy_scan(approvelist, global_list, data):
    """Verbatim pre-optimization implementation, used as the oracle."""
    for event in data.values():
        for good_item in approvelist + global_list:
            good_item = os.path.expandvars(good_item).replace('\\', '\\\\')
            try:
                if re.search(good_item, event, flags=re.IGNORECASE):
                    return True
            except re.error:
                return False
    return False


class ApprovelistCacheTests(unittest.TestCase):
    def setUp(self):
        self._orig_global = Noriben.global_approvelist
        self._orig_config = Noriben.config
        self._orig_debug_file = Noriben.debug_file
        Noriben.config = {'debug': False}
        Noriben.debug_file = ''
        Noriben.global_approvelist = ['procmon.exe']
        Noriben._approve_filter_cache.clear()

    def tearDown(self):
        Noriben.global_approvelist = self._orig_global
        Noriben.config = self._orig_config
        Noriben.debug_file = self._orig_debug_file
        Noriben._approve_filter_cache.clear()

    def _row(self, path, proc='malware.exe'):
        return {'Process Name': proc, 'PID': '1', 'Operation': 'CreateFile',
                'Path': path, 'Result': 'SUCCESS', 'Detail': 'Data: ' + path}

    def test_matches_are_detected(self):
        approvelist = [r'%%WinDir%%\\Prefetch\\*', 'wuauclt.exe']
        self.assertTrue(Noriben.approvelist_scan(approvelist, self._row('x', proc='wuauclt.exe')))

    def test_non_matches_are_not_approved(self):
        self.assertFalse(Noriben.approvelist_scan(['wuauclt.exe'],
                                                  self._row('C:\\evil.exe')))

    def test_semantics_match_legacy_implementation(self):
        approvelists = [['wuauclt.exe', r'Prefetch\\*'], ['jqs.exe'], []]
        paths = ['C:\\Windows\\Prefetch\\A.pf', 'C:\\evil.exe', 'procmon.exe',
                 'HKCU\\Software\\Run\\Evil']
        procs = ['malware.exe', 'wuauclt.exe', 'jqs.exe']
        for approvelist in approvelists:
            for path in paths:
                for proc in procs:
                    row = self._row(path, proc)
                    expected = _legacy_scan(approvelist, Noriben.global_approvelist, row)
                    self.assertEqual(Noriben.approvelist_scan(approvelist, row), expected,
                                     'diverged for {!r} / {!r}'.format(approvelist, row))

    def test_invalid_filter_returns_false_and_does_not_raise(self):
        # An unbalanced group is not a valid regex; legacy code returned False
        bad = ['this(is[invalid']
        row = self._row('C:\\evil.exe')
        self.assertFalse(Noriben.approvelist_scan(bad, row))
        # and it must be cached as invalid rather than recompiled every time
        compiled, _expanded = Noriben.compile_approve_filter('this(is[invalid')
        self.assertIsNone(compiled)

    def test_filters_are_compiled_once_and_reused(self):
        approvelist = ['wuauclt.exe']
        row = self._row('C:\\evil.exe')
        Noriben.approvelist_scan(approvelist, row)
        cached = dict(Noriben._approve_filter_cache)
        self.assertIn('wuauclt.exe', cached)
        Noriben.approvelist_scan(approvelist, row)
        # Same object reused -> no recompilation
        self.assertIs(Noriben._approve_filter_cache['wuauclt.exe'], cached['wuauclt.exe'])

    def test_environment_variables_are_expanded(self):
        os.environ['NORIBEN_TEST_DIR'] = 'SecretFolder'
        try:
            Noriben._approve_filter_cache.clear()
            compiled, expanded = Noriben.compile_approve_filter('$NORIBEN_TEST_DIR')
            self.assertIn('SecretFolder', expanded)
            self.assertIsNotNone(compiled)
        finally:
            del os.environ['NORIBEN_TEST_DIR']


class ExportRobustnessTests(unittest.TestCase):
    """A broken exporter must not abort parse_csv and lose the text report."""

    def setUp(self):
        self._orig_config = Noriben.config
        self._orig_debug_file = Noriben.debug_file
        Noriben.debug_file = ''

    def tearDown(self):
        Noriben.config = self._orig_config
        Noriben.debug_file = self._orig_debug_file

    def test_parse_csv_survives_a_failing_exporter(self):
        import csv
        import tempfile

        rows = [
            {'Time of Day': '1:01:01.1 PM', 'Process Name': 'mal.exe', 'PID': '1',
             'Operation': 'Process Create', 'Path': 'C:\\mal.exe', 'Result': 'SUCCESS',
             'Detail': 'PID: 2, Command line: vssadmin delete shadows /all'},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = os.path.join(tmp, 'run.csv')
            with open(csv_path, 'w', newline='', encoding='utf-8-sig') as handle:
                writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
                writer.writeheader()
                writer.writerows(rows)

            Noriben.config = dict(self._orig_config or {})
            Noriben.config.update({'debug': False, 'hash_type': 'SHA256',
                                   'generalize_paths': False, 'yara_folder': '',
                                   'output_folder': tmp, 'json_report': True,
                                   'disable-file-hash': True, 'troubleshoot': False})

            # Sabotage one exporter; the report must still be produced.
            original = Noriben.build_json_report
            Noriben.build_json_report = lambda *a, **k: (_ for _ in ()).throw(
                RuntimeError('exporter blew up'))
            try:
                report, timeline = [], []
                Noriben.parse_csv(csv_path, report, timeline)
            finally:
                Noriben.build_json_report = original

            joined = '\n'.join(report)
            self.assertIn('Processes Created:', joined)
            self.assertTrue(report, 'primary report must still be generated')


if __name__ == '__main__':
    unittest.main()
