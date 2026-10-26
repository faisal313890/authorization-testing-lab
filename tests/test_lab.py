import http.client
import json
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path
from lab import CASES, dispatch, evaluate, new_sandbox
from matrix import Client, run_matrix, write_reports
from server import LabServer


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.state = new_sandbox()

    def request(self, resource, method='GET', body=None, actor='alice', mode='hardened'):
        self.state[mode]['actor'] = actor
        return dispatch(self.state, mode, method, resource, body or {})

    def test_members_cannot_access_other_owners_even_same_tenant(self):
        for method in ('GET', 'PATCH'):
            with self.subTest(method=method):
                self.assertEqual(self.request('invoices/1002', method, {'note': 'tampered'})[0], 403)
        self.assertEqual(self.state['hardened']['invoices']['1002']['note'], 'Bob demo invoice')

    def test_owner_still_needs_matching_tenant(self):
        self.state['hardened']['users']['alice']['tenant'] = 'south'
        self.assertEqual(self.request('invoices/1001')[0], 403)

    def test_admin_is_tenant_scoped_for_read_and_update(self):
        for method in ('GET', 'PATCH'):
            with self.subTest(method=method):
                self.assertEqual(self.request('invoices/2001', method, {'note': 'tampered'}, 'admin')[0], 403)
        self.assertEqual(self.request('invoices/1002', actor='admin')[0], 200)

    def test_carol_can_access_south_but_not_north(self):
        self.assertEqual(self.request('invoices/2001', actor='carol')[0], 200)
        self.assertEqual(self.request('invoices/1001', actor='carol')[0], 403)

    def test_protected_fields_rejected_atomically(self):
        for field, value in [('role', 'admin'), ('tenant', 'south'), ('username', 'admin')]:
            with self.subTest(field=field):
                status, _, _ = self.request('profile', 'PATCH', {'display_name': 'tampered', field: value})
                self.assertEqual(status, 400)
                self.assertEqual(self.state['hardened']['users']['alice']['display_name'], 'Alice Demo')
                self.assertEqual(self.state['hardened']['users']['alice']['role'], 'member')
                self.assertEqual(self.state['hardened']['users']['alice']['tenant'], 'north')

    def test_valid_updates_have_expected_side_effects(self):
        self.assertEqual(self.request('profile', 'PATCH', {'display_name': 'Updated'})[0], 200)
        self.assertEqual(self.request('me')[1]['display_name'], 'Updated')
        self.assertEqual(self.request('invoices/1001', 'PATCH', {'note': 'Owner edit'})[0], 200)
        self.assertEqual(self.request('invoices/1001')[1]['note'], 'Owner edit')

    def test_invoice_fields_allowlisted_even_weak(self):
        for mode in ('weak', 'hardened'):
            self.assertEqual(self.request('invoices/1001', 'PATCH', {'note': 'x', 'owner': 'bob'}, mode=mode)[0], 400)

    def test_display_and_note_validation(self):
        for body in ({}, {'display_name': []}, {'display_name': ''}, {'display_name': 'x' * 81}):
            self.assertEqual(self.request('profile', 'PATCH', body)[0], 400)
        self.assertEqual(self.request('invoices/1001', 'PATCH', {'note': 2})[0], 400)
        self.assertEqual(self.request('invoices/1001', 'PATCH', {'note': 'x' * 201})[0], 400)

    def test_weak_escalation_reaches_admin_endpoint(self):
        self.assertEqual(self.request('profile', 'PATCH', {'role': 'admin'}, mode='weak')[0], 200)
        self.assertEqual(self.request('me', mode='weak')[1]['role'], 'admin')
        self.assertEqual(self.request('admin/users', mode='weak')[0], 200)
        self.assertEqual(self.request('admin/users')[0], 403)

    def test_unknown_method_and_identifier_fail_closed(self):
        for path, method in [('invoices/9999', 'GET'), ('invoices/1001', 'DELETE'), ('admin/unknown', 'GET')]:
            self.assertEqual(self.request(path, method)[0], 404)

    def test_unauthenticated_requests_denied_both_modes(self):
        for mode in ('weak', 'hardened'):
            for resource, method in [('invoices/1001', 'GET'), ('profile', 'PATCH'), ('admin/users', 'GET')]:
                self.assertEqual(self.request(resource, method, actor=None, mode=mode)[0], 401)

    def test_denied_responses_do_not_include_invoice(self):
        status, response, _ = self.request('invoices/1002')
        self.assertEqual(status, 403)
        self.assertEqual(set(response), {'error'})

    def test_authority_is_rechecked_after_role_change(self):
        self.assertEqual(self.request('admin/users', actor='admin')[0], 200)
        self.state['hardened']['users']['admin']['role'] = 'member'
        self.assertEqual(self.request('admin/users', actor='admin')[0], 403)

    def test_mode_data_does_not_leak(self):
        self.request('profile', 'PATCH', {'tenant': 'south'}, mode='weak')
        self.assertEqual(self.state['hardened']['users']['alice']['tenant'], 'north')

    def test_scope_evaluator_checks_content_not_status_only(self):
        case = next(c for c in CASES if c.get('check') == 'tenant_scope')
        self.assertFalse(all(evaluate(case, 200, {'users': []}).values()))
        self.assertFalse(all(evaluate(case, 200, {'users': list(self.state['weak']['users'].values())}).values()))


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = LabServer(('127.0.0.1', 0))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()
        cls.server.server_close()

    def setUp(self):
        self.client = Client(self.server.server_port)
        self.assertEqual(self.client.request('state')[0], 200)

    def raw(self, path, method='GET', body=None, headers=None):
        with closing(http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)) as connection:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()

    def test_http_matrix_expected_gaps(self):
        report = run_matrix(self.server.server_port)
        self.assertEqual(len(report['cases']), 26)
        gaps = [row for row in report['cases'] if not row['policy_match']]
        self.assertEqual(len(gaps), 8)
        self.assertEqual({row['mode'] for row in gaps}, {'weak'})
        self.assertEqual({row['id'] for row in gaps}, {'ATL-003', 'ATL-004', 'ATL-005', 'ATL-007', 'ATL-009', 'ATL-010', 'ATL-012', 'ATL-013'})
        for row in report['cases']:
            with self.subTest(mode=row['mode'], case=row['id']):
                if row['mode'] == 'hardened':
                    self.assertTrue(row['policy_match'])

    def test_separate_cookie_sandboxes(self):
        self.client.request('weak/profile', 'PATCH', {'role': 'admin'})
        other = Client(self.server.server_port)
        other.request('state')
        self.assertEqual(other.request('weak/me')[1]['role'], 'member')

    def test_reset_restores_seed_data(self):
        self.client.request('weak/profile', 'PATCH', {'role': 'admin'})
        self.client.control('reset', {})
        self.assertEqual(self.client.request('weak/me')[1]['role'], 'member')

    def test_rejects_bad_origin_host_and_cross_site(self):
        for headers in [{'Origin': 'https://external.test'}, {'Host': 'attacker.test'}, {'Sec-Fetch-Site': 'cross-site'}]:
            self.assertEqual(self.client.request('state', headers=headers)[0], 403)

    def test_no_custom_header_or_unknown_cookie_denied(self):
        self.assertEqual(self.raw('/api/state')[0], 403)
        self.assertEqual(self.client.request('hardened/me', headers={'Cookie': 'atl_session=forged'})[0], 401)

    def test_cookie_attributes_and_security_headers(self):
        status, headers, _ = self.raw('/api/state', headers={'X-Authorization-Lab': 'local'})
        self.assertEqual(status, 200)
        self.assertIn('HttpOnly', headers['Set-Cookie'])
        self.assertIn('SameSite=Strict', headers['Set-Cookie'])
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])

    def test_static_allowlist(self):
        for path in ('/', '/app.js', '/style.css'):
            self.assertEqual(self.raw(path)[0], 200)
        for path in ('/server.py', '/../lab.py', '/static/../lab.py'):
            self.assertEqual(self.raw(path)[0], 404)

    def test_invalid_json_and_limits(self):
        headers = {'X-Authorization-Lab': 'local', 'Content-Type': 'application/json', 'Cookie': self.client.cookie}
        for body in ('{', '[]', 'null'):
            self.assertEqual(self.raw('/api/persona', 'POST', body, headers)[0], 400)
        self.assertEqual(self.raw('/api/persona', 'POST', 'x' * 4097, headers)[0], 413)
        self.assertEqual(self.raw('/api/persona', 'POST', '{}', {'X-Authorization-Lab': 'local'})[0], 415)

    def test_persona_is_validated(self):
        for value in ('unknown', [], {'role': 'admin'}):
            self.assertEqual(self.client.request('persona', 'POST', {'username': value})[0], 400)
        self.assertEqual(self.client.request('persona', 'POST', {'username': 'alice', 'role': 'admin'})[0], 400)

    def test_session_expiry(self):
        sid = self.client.cookie.split('=', 1)[1]
        with self.server.lock:
            self.server.sessions[sid]['touched'] -= 7201
        self.assertEqual(self.client.request('hardened/me')[0], 401)

    def test_exports_no_session_cookie(self):
        report = run_matrix(self.server.server_port)
        with tempfile.TemporaryDirectory() as directory:
            write_reports(report, directory)
            text = (Path(directory) / 'authorization-matrix.json').read_text()
            self.assertNotIn('atl_session', text)
            self.assertEqual(len(json.loads(text)['cases']), 26)
            import csv
            with (Path(directory) / 'authorization-matrix.csv').open(encoding='utf-8-sig', newline='') as stream:
                self.assertEqual(len(list(csv.reader(stream))), 27)

    def test_audit_is_bounded(self):
        for _ in range(205):
            self.client.request('hardened/me')
        self.assertEqual(len(self.client.request('audit')[1]['entries']), 200)

    def test_nonloopback_binding_refused(self):
        with self.assertRaises(ValueError):
            LabServer(('0.0.0.0', 0))


if __name__ == '__main__':
    unittest.main()
