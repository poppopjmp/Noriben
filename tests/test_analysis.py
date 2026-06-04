"""
Unit tests for the reverse-engineer triage engine: IOC extraction, heuristic
MITRE ATT&CK tagging, and JSON report assembly.

These feed analyze_indicators() the exact line formats that parse_csv()
produces, so the parsing stays in sync with the report writer.

Run with:  python -m unittest discover -s tests -v
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import Noriben  # noqa: E402

SHA = 'a' * 64

PROCESS_OUTPUT = [
    '[CreateProcess] malware.exe:1234 > powershell.exe -enc SQBFAFgAaGVsbG8gd29ybGQ=\t[Child PID: 5678]',
    '[CreateProcess] malware.exe:1234 > schtasks /create /tn evil /tr c:\\evil.exe\t[Child PID: 9012]',
]
FILE_OUTPUT = [
    '[CreateFile] malware.exe:1234 > C:\\Users\\x\\AppData\\Roaming\\evil.exe\t[SHA256: {}]'.format(SHA),
    '[DeleteFile] malware.exe:1234 > C:\\Users\\x\\temp.tmp',
    '[RenameFile] malware.exe:1234 > C:\\a.tmp => C:\\b.exe',
]
REG_OUTPUT = [
    '[RegSetValue] malware.exe:1234 > HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil  =  C:\\evil.exe',
    '[RegCreateKey] malware.exe:1234 > HKLM\\System\\CurrentControlSet\\Services\\EvilSvc',
]
NET_OUTPUT = ['[TCP] malware.exe:1234 > 1.2.3.4:443']
REMOTE_SERVERS = ['1.2.3.4', 'evil.com', 'evil.com']


def _indicators():
    return Noriben.analyze_indicators(PROCESS_OUTPUT, FILE_OUTPUT, REG_OUTPUT,
                                      NET_OUTPUT, REMOTE_SERVERS, 'SHA256')


class AnalyzeIndicatorsTests(unittest.TestCase):
    def test_processes_parsed(self):
        ind = _indicators()
        self.assertEqual(len(ind['processes']), 2)
        first = ind['processes'][0]
        self.assertEqual(first['process'], 'malware.exe')
        self.assertEqual(first['pid'], '1234')
        self.assertIn('powershell', first['command_line'])
        self.assertEqual(first['child_pid'], '5678')

    def test_files_created_with_hash(self):
        ind = _indicators()
        created = ind['files_created']
        self.assertEqual(created[0]['path'], 'C:\\Users\\x\\AppData\\Roaming\\evil.exe')
        self.assertEqual(created[0]['hash'], SHA)

    def test_dropped_hashes_deduped(self):
        ind = _indicators()
        self.assertEqual(len(ind['dropped_file_hashes']), 1)
        self.assertEqual(ind['dropped_file_hashes'][0]['hash'], SHA)
        self.assertEqual(ind['dropped_file_hashes'][0]['hash_type'], 'SHA256')

    def test_deleted_and_renamed(self):
        ind = _indicators()
        self.assertEqual(ind['files_deleted'], ['C:\\Users\\x\\temp.tmp'])
        self.assertEqual(ind['files_renamed'][0], {'from': 'C:\\a.tmp', 'to': 'C:\\b.exe'})

    def test_registry_parsed(self):
        ind = _indicators()
        ops = {r['operation'] for r in ind['registry']}
        self.assertEqual(ops, {'RegSetValue', 'RegCreateKey'})
        run_entry = next(r for r in ind['registry'] if r['operation'] == 'RegSetValue')
        self.assertTrue(run_entry['key'].endswith('Run\\evil'))
        self.assertEqual(run_entry['data'], 'C:\\evil.exe')

    def test_network_hosts_sorted_unique(self):
        ind = _indicators()
        self.assertEqual(ind['network_hosts'], ['1.2.3.4', 'evil.com'])

    def test_malformed_lines_ignored(self):
        ind = Noriben.analyze_indicators(['garbage line'], ['also garbage'], [], [], [], 'SHA256')
        self.assertEqual(ind['processes'], [])
        self.assertEqual(ind['files_created'], [])


class AttackTechniqueTests(unittest.TestCase):
    def setUp(self):
        self.techniques = Noriben.detect_attack_techniques(_indicators())
        self.ids = {t['id'] for t in self.techniques}

    def test_run_key_persistence(self):
        self.assertIn('T1547.001', self.ids)

    def test_service_creation(self):
        self.assertIn('T1543.003', self.ids)

    def test_powershell_and_encoded(self):
        self.assertIn('T1059.001', self.ids)
        self.assertIn('T1027', self.ids)

    def test_scheduled_task(self):
        self.assertIn('T1053.005', self.ids)

    def test_file_deletion_and_network(self):
        self.assertIn('T1070.004', self.ids)
        self.assertIn('T1071', self.ids)

    def test_evidence_attached_and_capped(self):
        for technique in self.techniques:
            self.assertTrue(technique['evidence'])
            self.assertLessEqual(len(technique['evidence']), 5)

    def test_sorted_by_id(self):
        self.assertEqual(self.ids, {t['id'] for t in self.techniques})
        ids_list = [t['id'] for t in self.techniques]
        self.assertEqual(ids_list, sorted(ids_list))

    def test_benign_run_has_no_techniques(self):
        benign = Noriben.analyze_indicators(
            ['[CreateProcess] notepad.exe:10 > notepad.exe readme.txt\t[Child PID: 11]'],
            [], [], [], [], 'SHA256')
        self.assertEqual(Noriben.detect_attack_techniques(benign), [])


class JsonReportTests(unittest.TestCase):
    def test_structure_and_serializable(self):
        ind = _indicators()
        techniques = Noriben.detect_attack_techniques(ind)
        metadata = {'version': '9.9.9', 'generated': '2026-06-04T00:00:00'}
        report = Noriben.build_json_report(ind, techniques, metadata)

        self.assertEqual(report['noriben']['version'], '9.9.9')
        self.assertEqual(report['summary']['processes'], 2)
        self.assertEqual(report['summary']['files_created'], 1)
        self.assertEqual(report['summary']['registry_writes'], 2)
        self.assertEqual(report['iocs']['file_hashes'][0]['hash'], SHA)
        self.assertEqual(report['network']['hosts'], ['1.2.3.4', 'evil.com'])

        # Must round-trip through JSON cleanly
        text = json.dumps(report)
        self.assertEqual(json.loads(text)['summary']['attack_techniques'], len(techniques))


class FormatSectionTests(unittest.TestCase):
    def test_section_contains_header_and_techniques(self):
        ind = _indicators()
        techniques = Noriben.detect_attack_techniques(ind)
        lines = Noriben.format_analysis_section(ind, techniques)
        blob = '\n'.join(lines)
        self.assertIn('Behavioral Summary & Indicators of Compromise:', blob)
        self.assertIn('MITRE ATT&CK techniques observed', blob)
        self.assertIn('T1547.001', blob)
        self.assertIn(SHA, blob)
        self.assertIn('evil.com', blob)

    def test_empty_run_reports_no_techniques(self):
        ind = Noriben.analyze_indicators([], [], [], [], [], 'SHA256')
        lines = Noriben.format_analysis_section(ind, [])
        self.assertIn('No notable ATT&CK techniques', '\n'.join(lines))


if __name__ == '__main__':
    unittest.main()
