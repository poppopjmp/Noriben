"""
Unit tests for network_split_host_port(), the IPv6-safe host/port splitter
merged from upstream Noriben v2.0.4.

Run with:  python -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import Noriben  # noqa: E402


class NetworkSplitHostPortTests(unittest.TestCase):
    def test_hostname_with_port(self):
        self.assertEqual(Noriben.network_split_host_port('example.com:443'),
                         ('example.com', '443'))

    def test_hostname_without_port(self):
        self.assertEqual(Noriben.network_split_host_port('example.com'),
                         ('example.com', None))

    def test_ipv4_without_port(self):
        self.assertEqual(Noriben.network_split_host_port('192.168.1.1'),
                         ('192.168.1.1', None))

    def test_ipv4_with_port(self):
        self.assertEqual(Noriben.network_split_host_port('192.168.1.1:8080'),
                         ('192.168.1.1', '8080'))

    def test_bare_ipv6_is_not_split(self):
        # A bare IPv6 address must not be mangled by naive ':' splitting
        self.assertEqual(Noriben.network_split_host_port('2001:db8::1'),
                         ('2001:db8::1', None))

    def test_bracketed_ipv6_with_port(self):
        self.assertEqual(Noriben.network_split_host_port('[2001:db8::1]:443'),
                         ('2001:db8::1', '443'))

    def test_loopback_ipv6(self):
        self.assertEqual(Noriben.network_split_host_port('::1'),
                         ('::1', None))

    def test_whitespace_is_stripped(self):
        self.assertEqual(Noriben.network_split_host_port('  example.com:80  '),
                         ('example.com', '80'))


if __name__ == '__main__':
    unittest.main()
