"""
Unit tests for the AI-assisted report analysis feature in Noriben.

These tests exercise the LLM client logic without any network access by
substituting a fake ``requests`` module onto the Noriben module. Run with:

    python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest

# Allow running from anywhere by adding the repo root to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import Noriben  # noqa: E402


class _FakeResponse:
    def __init__(self, status_code=200, payload=None, text=''):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError('no json')
        return self._payload


class _FakeRequestException(Exception):
    pass


class _FakeExceptions:
    RequestException = _FakeRequestException


class _FakeRequests:
    """Minimal stand-in for the ``requests`` module used by Noriben."""

    exceptions = _FakeExceptions

    def __init__(self, response=None, raise_exc=None):
        self._response = response
        self._raise_exc = raise_exc
        self.last_url = None
        self.last_headers = None
        self.last_json = None
        self.last_timeout = None

    def post(self, url, headers=None, json=None, timeout=None):
        self.last_url = url
        self.last_headers = headers
        self.last_json = json
        self.last_timeout = timeout
        if self._raise_exc:
            raise self._raise_exc
        return self._response


def _ok_response(content='## Analysis\nMalicious.'):
    return _FakeResponse(200, {'choices': [{'message': {'content': content}}]})


class AIAnalysisTests(unittest.TestCase):
    def setUp(self):
        # log_debug() reads the global config/debug_file; give it safe values
        self._orig_requests = Noriben.requests
        self._orig_config = Noriben.config
        self._orig_debug_file = Noriben.debug_file
        Noriben.config = {'debug': False}
        Noriben.debug_file = ''

    def tearDown(self):
        Noriben.requests = self._orig_requests
        Noriben.config = self._orig_config
        Noriben.debug_file = self._orig_debug_file

    def test_returns_empty_when_requests_missing(self):
        Noriben.requests = None
        result = Noriben.generate_ai_analysis(['some report'], {'ai_provider': 'ollama'})
        self.assertEqual(result, '')

    def test_successful_analysis_returns_content(self):
        fake = _FakeRequests(response=_ok_response('Verdict: Malicious'))
        Noriben.requests = fake
        result = Noriben.generate_ai_analysis(['Processes Created:', 'evil.exe'],
                                              {'ai_provider': 'ollama', 'ai_model': 'llama3.1'})
        self.assertEqual(result, 'Verdict: Malicious')
        self.assertEqual(fake.last_json['model'], 'llama3.1')
        # System + user messages should be present
        roles = [m['role'] for m in fake.last_json['messages']]
        self.assertEqual(roles, ['system', 'user'])
        self.assertIn('evil.exe', fake.last_json['messages'][1]['content'])

    def test_ollama_default_endpoint_and_model(self):
        fake = _FakeRequests(response=_ok_response())
        Noriben.requests = fake
        Noriben.generate_ai_analysis(['x'], {'ai_provider': 'ollama'})
        self.assertEqual(fake.last_url, 'http://localhost:11434/v1/chat/completions')
        self.assertEqual(fake.last_json['model'], 'llama3.1')
        # No API key -> no Authorization header
        self.assertNotIn('Authorization', fake.last_headers)

    def test_openai_default_endpoint_and_auth_header(self):
        fake = _FakeRequests(response=_ok_response())
        Noriben.requests = fake
        Noriben.generate_ai_analysis(['x'], {'ai_provider': 'openai', 'ai_api_key': 'sk-test'})
        self.assertEqual(fake.last_url, 'https://api.openai.com/v1/chat/completions')
        self.assertEqual(fake.last_json['model'], 'gpt-4o-mini')
        self.assertEqual(fake.last_headers['Authorization'], 'Bearer sk-test')

    def test_custom_base_url_is_normalized(self):
        fake = _FakeRequests(response=_ok_response())
        Noriben.requests = fake
        Noriben.generate_ai_analysis(['x'], {'ai_base_url': 'http://host:1234/v1/'})
        self.assertEqual(fake.last_url, 'http://host:1234/v1/chat/completions')

    def test_report_truncation(self):
        fake = _FakeRequests(response=_ok_response())
        Noriben.requests = fake
        big = ['A' * 1000]
        Noriben.generate_ai_analysis(big, {'ai_max_chars': 100})
        sent = fake.last_json['messages'][1]['content']
        self.assertIn('truncated', sent)

    def test_http_error_returns_empty(self):
        fake = _FakeRequests(response=_FakeResponse(500, None, 'server error'))
        Noriben.requests = fake
        self.assertEqual(Noriben.generate_ai_analysis(['x'], {}), '')

    def test_request_exception_returns_empty(self):
        fake = _FakeRequests(raise_exc=_FakeRequestException('connection refused'))
        Noriben.requests = fake
        self.assertEqual(Noriben.generate_ai_analysis(['x'], {}), '')

    def test_malformed_response_returns_empty(self):
        fake = _FakeRequests(response=_FakeResponse(200, {'unexpected': True}))
        Noriben.requests = fake
        self.assertEqual(Noriben.generate_ai_analysis(['x'], {}), '')


class AppendAIAnalysisTests(unittest.TestCase):
    def setUp(self):
        self._orig_requests = Noriben.requests
        self._orig_config = Noriben.config
        self._orig_debug_file = Noriben.debug_file
        Noriben.config = {'debug': False}
        Noriben.debug_file = ''

    def tearDown(self):
        Noriben.requests = self._orig_requests
        Noriben.config = self._orig_config
        Noriben.debug_file = self._orig_debug_file

    def test_disabled_does_nothing(self):
        report = ['line1']
        with tempfile.TemporaryDirectory() as tmp:
            ai_file = os.path.join(tmp, 'out.md')
            Noriben.append_ai_analysis(report, {'ai_enabled': False}, ai_file)
            self.assertEqual(report, ['line1'])
            self.assertFalse(os.path.exists(ai_file))

    def test_enabled_appends_and_writes_file(self):
        Noriben.requests = _FakeRequests(response=_ok_response('VERDICT: Malicious'))
        report = ['Existing report line']
        with tempfile.TemporaryDirectory() as tmp:
            ai_file = os.path.join(tmp, 'out.md')
            Noriben.append_ai_analysis(report,
                                       {'ai_enabled': True, 'ai_provider': 'ollama'},
                                       ai_file)
            self.assertIn('AI Analysis:', report)
            self.assertIn('VERDICT: Malicious', report)
            self.assertTrue(os.path.exists(ai_file))
            with open(ai_file, encoding='utf-8') as handle:
                self.assertIn('VERDICT: Malicious', handle.read())

    def test_enabled_but_failure_leaves_report_untouched(self):
        Noriben.requests = _FakeRequests(raise_exc=_FakeRequestException('down'))
        report = ['Existing report line']
        with tempfile.TemporaryDirectory() as tmp:
            ai_file = os.path.join(tmp, 'out.md')
            Noriben.append_ai_analysis(report,
                                       {'ai_enabled': True, 'ai_provider': 'ollama'},
                                       ai_file)
            self.assertEqual(report, ['Existing report line'])
            self.assertFalse(os.path.exists(ai_file))


if __name__ == '__main__':
    unittest.main()
