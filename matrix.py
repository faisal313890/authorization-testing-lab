"""Run the matrix against a fresh ephemeral loopback server; no remote targets."""
import argparse
import csv
import http.client
import json
import threading
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from lab import CASES, evaluate
from server import LabServer


class Client:
    def __init__(self, port):
        self.port = port
        self.cookie = None

    def request(self, path, method='GET', body=None, headers=None):
        request_headers = {'X-Authorization-Lab': 'local'}
        if self.cookie:
            request_headers['Cookie'] = self.cookie
        raw = None
        if body is not None:
            raw = json.dumps(body).encode()
            request_headers['Content-Type'] = 'application/json'
        request_headers.update(headers or {})
        with closing(http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)) as conn:
            conn.request(method, '/api/' + path, body=raw, headers=request_headers)
            response = conn.getresponse()
            if response.getheader('Set-Cookie'):
                self.cookie = response.getheader('Set-Cookie').split(';', 1)[0]
            return response.status, json.loads(response.read())

    def control(self, path, body):
        status, response = self.request(path, 'POST', body)
        if status != 200:
            raise RuntimeError(f'Lab control failed: {status}: {response}')


def run_matrix(port):
    client = Client(port)
    status, state = client.request('state')
    if status != 200 or state.get('app') != 'Authorization Testing Lab':
        raise RuntimeError('Not the expected local lab.')
    rows = []
    try:
        for mode in ('weak', 'hardened'):
            for case in CASES:
                client.control('reset', {})
                client.control('persona', {'username': case['actor']})
                status, response = client.request(mode + '/' + case['path'], case['method'], case.get('body'))
                followup = client.request(mode + '/' + case['followup']) if case.get('followup') else None
                checks = evaluate(case, status, response, followup)
                rows.append({**case, 'mode': mode, 'observed': {'status': status, 'body': response},
                             'followup': {'status': followup[0], 'body': followup[1]} if followup else None,
                             'checks': checks, 'policy_match': all(checks.values())})
    finally:
        client.control('reset', {})
    return {'tool': 'Authorization Testing Lab', 'version': '0.1', 'report_id': str(uuid.uuid4()),
            'observed_at': datetime.now(timezone.utc).isoformat(),
            'scope': '13 seeded cases per mode, over an ephemeral loopback HTTP server; fresh data for each case.',
            'limits': ['Synthetic local policy only; not an external website assessment.',
                       'Persona selection simulates authentication.',
                       'No TLS, credential, race-condition or exhaustive authorization audit.',
                       'MATCH means only the listed assertions passed.'], 'cases': rows}


def csv_value(value):
    text = str(value)
    return "'" + text if text.lstrip().startswith(('=', '+', '-', '@')) else text


def write_reports(report, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'authorization-matrix.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    with (output / 'authorization-matrix.csv').open('w', encoding='utf-8-sig', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['report_id', 'observed_at', 'case_id', 'mode', 'title', 'actor', 'method', 'path',
                         'expected_status', 'observed_status', 'policy_match', 'checks'])
        for row in report['cases']:
            writer.writerow([csv_value(x) for x in [report['report_id'], report['observed_at'], row['id'], row['mode'],
                row['title'], row['actor'] or 'anonymous', row['method'], row['path'], row['expected'],
                row['observed']['status'], row['policy_match'], json.dumps(row['checks'])]])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='reports', help='Local report directory (default: reports).')
    args = parser.parse_args()
    with LabServer(('127.0.0.1', 0)) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            report = run_matrix(server.server_port)
        finally:
            server.shutdown()
            thread.join()
    write_reports(report, args.output)
    for mode in ('weak', 'hardened'):
        rows = [r for r in report['cases'] if r['mode'] == mode]
        print(f"{mode}: {sum(r['policy_match'] for r in rows)}/{len(rows)} policy matches")
    print(f'Reports written to {Path(args.output).resolve()}')


if __name__ == '__main__':
    main()
