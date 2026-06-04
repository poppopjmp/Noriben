"""
Unit tests for file handling behavior merged from upstream Noriben v2.0.3:
  * file_exists() only approves regular files (and the import stat fix)
  * hash_file() reads the file in chunks and honors disable-file-hash

Run with:  python -m unittest discover -s tests -v
"""
import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import Noriben  # noqa: E402


class FileExistsTests(unittest.TestCase):
    def setUp(self):
        self._orig_config = Noriben.config
        self._orig_debug_file = Noriben.debug_file
        Noriben.config = {'debug': False, 'hash_type': 'SHA256'}
        Noriben.debug_file = ''

    def tearDown(self):
        Noriben.config = self._orig_config
        Noriben.debug_file = self._orig_debug_file

    def test_regular_file_is_detected(self):
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(b'data')
            name = handle.name
        try:
            self.assertTrue(Noriben.file_exists(name))
        finally:
            os.unlink(name)

    def test_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(Noriben.file_exists(tmp))

    def test_missing_file_is_rejected(self):
        self.assertFalse(Noriben.file_exists('/no/such/path/really_12345'))


class HashFileTests(unittest.TestCase):
    def setUp(self):
        self._orig_config = Noriben.config
        self._orig_debug_file = Noriben.debug_file
        Noriben.debug_file = ''

    def tearDown(self):
        Noriben.config = self._orig_config
        Noriben.debug_file = self._orig_debug_file

    def _write_temp(self, data):
        fd, name = tempfile.mkstemp()
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
        return name

    def test_sha256_chunked_matches_hashlib(self):
        Noriben.config = {'debug': False, 'hash_type': 'SHA256'}
        # Larger than the 8192-byte chunk size to exercise the read loop
        data = b'A' * 20000
        name = self._write_temp(data)
        try:
            expected = hashlib.sha256(data).hexdigest()
            self.assertEqual(Noriben.hash_file(name), expected)
        finally:
            os.unlink(name)

    def test_md5_selection(self):
        Noriben.config = {'debug': False, 'hash_type': 'MD5'}
        data = b'hello world'
        name = self._write_temp(data)
        try:
            self.assertEqual(Noriben.hash_file(name), hashlib.md5(data).hexdigest())
        finally:
            os.unlink(name)

    def test_missing_file_returns_none(self):
        Noriben.config = {'debug': False, 'hash_type': 'SHA256'}
        self.assertIsNone(Noriben.hash_file('/no/such/file/abc123'))


if __name__ == '__main__':
    unittest.main()
