"""Intentionally vulnerable authorization exercises; synthetic in-memory data only."""
from copy import deepcopy

USERS = {
    'alice': {'username': 'alice', 'display_name': 'Alice Demo', 'role': 'member', 'tenant': 'north'},
    'bob': {'username': 'bob', 'display_name': 'Bob Demo', 'role': 'member', 'tenant': 'north'},
    'carol': {'username': 'carol', 'display_name': 'Carol Demo', 'role': 'member', 'tenant': 'south'},
    'admin': {'username': 'admin', 'display_name': 'North Admin', 'role': 'admin', 'tenant': 'north'},
}
INVOICES = {
    '1001': {'id': '1001', 'owner': 'alice', 'tenant': 'north', 'amount': '125.00', 'note': 'Alice demo invoice'},
    '1002': {'id': '1002', 'owner': 'bob', 'tenant': 'north', 'amount': '240.00', 'note': 'Bob demo invoice'},
    '2001': {'id': '2001', 'owner': 'carol', 'tenant': 'south', 'amount': '360.00', 'note': 'Carol demo invoice'},
}
MODES = ('weak', 'hardened')


def new_sandbox():
    return {m: {'users': deepcopy(USERS), 'invoices': deepcopy(INVOICES), 'actor': 'alice'} for m in MODES}


def can_access_invoice(user, invoice):
    """Tenant boundary applies to owners AND administrators."""
    return user['tenant'] == invoice['tenant'] and (
        user['username'] == invoice['owner'] or user['role'] == 'admin')


def dispatch(state, mode, method, resource, body):
    """Same dispatcher serves browser and integration tests. Defaults deny."""
    data = state[mode]
    user = data['users'].get(data['actor'])
    if user is None:
        return 401, {'error': 'Choose a demo persona first.'}, 'No authenticated demo persona'
    if resource == 'me' and method == 'GET':
        return 200, deepcopy(user), 'Current server-side persona'
    if resource == 'profile' and method == 'PATCH':
        allowed = {'display_name'} if mode == 'hardened' else {'display_name', 'role', 'tenant'}
        if not body or set(body) - allowed:
            return 400, {'error': 'Unsupported profile fields.'}, 'Writable-field allowlist rejected the request'
        if any(not isinstance(v, str) or not v.strip() or len(v) > 80 for v in body.values()):
            return 400, {'error': 'Profile values must be non-empty strings up to 80 characters.'}, 'Invalid input'
        if ('role' in body and body['role'] not in ('member', 'admin')) or (
                'tenant' in body and body['tenant'] not in ('north', 'south')):
            return 400, {'error': 'Unknown role or tenant.'}, 'Invalid input'
        # Deliberate weak-mode mass assignment. Never copy this into a real application.
        user.update(body)
        return 200, deepcopy(user), ('Only display_name is writable' if mode == 'hardened'
                                     else 'VULNERABLE: client fields updated protected attributes')
    if resource == 'admin/users' and method == 'GET':
        if mode == 'hardened' and user['role'] != 'admin':
            return 403, {'error': 'Tenant administrator role required.'}, 'Server-side role check denied'
        users = [deepcopy(u) for u in data['users'].values()
                 if mode == 'weak' or u['tenant'] == user['tenant']]
        return 200, {'users': users}, ('Role and tenant scope enforced' if mode == 'hardened'
                                      else 'VULNERABLE: role and tenant scope were not checked')
    parts = resource.split('/')
    if len(parts) == 2 and parts[0] == 'invoices' and method in ('GET', 'PATCH'):
        invoice = data['invoices'].get(parts[1])
        if invoice is None:
            return 404, {'error': 'Invoice not found.'}, 'Unknown invoice identifier'
        if mode == 'hardened' and not can_access_invoice(user, invoice):
            return 403, {'error': 'Invoice access denied.'}, 'Owner/admin AND tenant check denied'
        if method == 'PATCH':
            if set(body) != {'note'} or not isinstance(body['note'], str) or len(body['note']) > 200:
                return 400, {'error': 'Supply only note (string, up to 200 characters).'}, 'Invalid input'
            invoice['note'] = body['note']
        return 200, deepcopy(invoice), ('Owner/admin AND tenant check allowed' if mode == 'hardened'
                                        else 'VULNERABLE: invoice ownership and tenant were not checked')
    return 404, {'error': 'Unknown operation.'}, 'No matching operation; denied by default'


# Expected results express the intended policy, including when weak mode violates it.
CASES = [
    {'id': 'ATL-001', 'title': 'Anonymous invoice read', 'actor': None, 'method': 'GET', 'path': 'invoices/1001', 'expected': 401},
    {'id': 'ATL-002', 'title': 'Owner reads own invoice', 'actor': 'alice', 'method': 'GET', 'path': 'invoices/1001', 'expected': 200},
    {'id': 'ATL-003', 'title': 'Member reads peer invoice', 'actor': 'alice', 'method': 'GET', 'path': 'invoices/1002', 'expected': 403},
    {'id': 'ATL-004', 'title': 'Member reads across tenants', 'actor': 'alice', 'method': 'GET', 'path': 'invoices/2001', 'expected': 403},
    {'id': 'ATL-005', 'title': 'Member edits peer invoice', 'actor': 'alice', 'method': 'PATCH', 'path': 'invoices/1002', 'body': {'note': 'Changed by Alice in the lab'}, 'expected': 403},
    {'id': 'ATL-006', 'title': 'Owner edits own invoice', 'actor': 'alice', 'method': 'PATCH', 'path': 'invoices/1001', 'body': {'note': 'Owner update in the lab'}, 'expected': 200},
    {'id': 'ATL-007', 'title': 'Member accesses admin listing', 'actor': 'alice', 'method': 'GET', 'path': 'admin/users', 'expected': 403},
    {'id': 'ATL-008', 'title': 'Tenant admin reads peer invoice', 'actor': 'admin', 'method': 'GET', 'path': 'invoices/1002', 'expected': 200},
    {'id': 'ATL-009', 'title': 'Tenant admin reads another tenant', 'actor': 'admin', 'method': 'GET', 'path': 'invoices/2001', 'expected': 403},
    {'id': 'ATL-010', 'title': 'Admin listing stays within tenant', 'actor': 'admin', 'method': 'GET', 'path': 'admin/users', 'expected': 200, 'check': 'tenant_scope'},
    {'id': 'ATL-011', 'title': 'Member changes display name', 'actor': 'alice', 'method': 'PATCH', 'path': 'profile', 'body': {'display_name': 'Alice Updated'}, 'expected': 200},
    {'id': 'ATL-012', 'title': 'Member assigns own admin role', 'actor': 'alice', 'method': 'PATCH', 'path': 'profile', 'body': {'role': 'admin'}, 'expected': 400, 'followup': 'admin/users', 'followup_expected': 403},
    {'id': 'ATL-013', 'title': 'Member assigns own tenant', 'actor': 'alice', 'method': 'PATCH', 'path': 'profile', 'body': {'tenant': 'south'}, 'expected': 400, 'followup': 'me', 'check': 'tenant_unchanged'},
]


def evaluate(case, status, response, followup=None):
    checks = {'status_matches': status == case['expected']}
    if case.get('check') == 'tenant_scope':
        users = response.get('users')
        checks['tenant_scope'] = (isinstance(users, list) and len(users) == 3
                                  and {u.get('username') for u in users} == {'alice', 'bob', 'admin'}
                                  and all(u.get('tenant') == 'north' for u in users))
    if 'followup_expected' in case:
        checks['followup_status_matches'] = bool(followup and followup[0] == case['followup_expected'])
    if case.get('check') == 'tenant_unchanged':
        checks['tenant_unchanged'] = bool(followup and followup[0] == 200 and followup[1].get('tenant') == 'north')
    return checks
