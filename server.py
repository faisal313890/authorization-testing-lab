"""Loopback-only educational HTTP server. Not a deployable authentication service."""
import json
import os
import secrets
import threading
import time
import webbrowser
from http.cookies import SimpleCookie, CookieError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from lab import CASES, USERS, INVOICES, MODES, dispatch, new_sandbox

ROOT = Path(__file__).resolve().parent
MAX_BODY = 4096
SESSION_TTL = 7200


class LabServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address):
        if address[0] != '127.0.0.1':
            raise ValueError('This lab must bind to 127.0.0.1.')
        super().__init__(address, Handler)
        self.sessions = {}
        self.lock = threading.RLock()


class Handler(BaseHTTPRequestHandler):
    server_version = 'AuthorizationLab/0.1'

    def log_message(self, *args):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def reply(self, status, data, cookie=None, content_type='application/json; charset=utf-8'):
        raw = data if isinstance(data, bytes) else json.dumps(data, ensure_ascii=True).encode()
        self.send_response(status)
        for k, v in {
            'Content-Type': content_type, 'Content-Length': str(len(raw)), 'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
            'X-Frame-Options': 'DENY', 'Connection': 'close',
            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        }.items():
            self.send_header(k, v)
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(raw)
        self.close_connection = True

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def do_PATCH(self):
        self.handle_request()

    def handle_request(self):
        port = self.server.server_port
        hosts = {f'127.0.0.1:{port}', f'localhost:{port}'}
        origin = self.headers.get('Origin')
        if self.headers.get('Host') not in hosts or (origin is not None and origin not in {f'http://{h}' for h in hosts}):
            return self.reply(403, {'error': 'Local Host/Origin required.'})
        if self.headers.get('Sec-Fetch-Site') == 'cross-site':
            return self.reply(403, {'error': 'Cross-site requests are not accepted.'})
        parsed = urlsplit(self.path)
        if parsed.query or parsed.fragment or parsed.scheme or parsed.netloc:
            return self.reply(400, {'error': 'Use a relative lab path without query parameters.'})
        path = parsed.path
        if self.command == 'GET' and path in ('/', '/app.js', '/style.css'):
            filename, content_type = {
                '/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                '/style.css': ('style.css', 'text/css; charset=utf-8'),
            }[path]
            return self.reply(200, (ROOT / 'static' / filename).read_bytes(), content_type=content_type)
        if not path.startswith('/api/'):
            return self.reply(404, {'error': 'Not found.'})
        if self.headers.get('X-Authorization-Lab') != 'local':
            return self.reply(403, {'error': 'Lab request header required.'})
        body = {}
        if self.command in ('POST', 'PATCH'):
            if self.headers.get('Transfer-Encoding'):
                return self.reply(400, {'error': 'Transfer encoding is unsupported.'})
            try:
                length = int(self.headers.get('Content-Length', '-1'))
            except ValueError:
                length = -1
            if not 0 <= length <= MAX_BODY:
                return self.reply(413, {'error': 'Supply a JSON body up to 4096 bytes.'})
            if self.headers.get('Content-Type', '').split(';')[0].strip().lower() != 'application/json':
                return self.reply(415, {'error': 'JSON required.'})
            try:
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise ValueError
            except (ValueError, UnicodeError, RecursionError):
                return self.reply(400, {'error': 'Invalid JSON object.'})
        try:
            cookie = SimpleCookie(self.headers.get('Cookie', ''))
            sid = cookie['atl_session'].value if 'atl_session' in cookie else None
        except CookieError:
            sid = None
        with self.server.lock:
            now = time.monotonic()
            for key in list(self.server.sessions):
                if now - self.server.sessions[key]['touched'] > SESSION_TTL:
                    del self.server.sessions[key]
            session = self.server.sessions.get(sid)
            new_cookie = None
            if session is None:
                if path != '/api/state' or self.command != 'GET':
                    return self.reply(401, {'error': 'Open the lab first; this session may have expired.'})
                if len(self.server.sessions) >= 64:
                    return self.reply(503, {'error': 'Lab session limit reached. Restart the server.'})
                sid = secrets.token_urlsafe(32)
                session = {'state': new_sandbox(), 'audit': [], 'touched': now}
                self.server.sessions[sid] = session
                # HTTP loopback practice only; no production Secure-cookie claim.
                new_cookie = f'atl_session={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL}'
            session['touched'] = now
            if path == '/api/state' and self.command == 'GET':
                return self.reply(200, {'app': 'Authorization Testing Lab', 'version': '0.1', 'cases': CASES,
                    'accounts': list(USERS.values()), 'invoices': list(INVOICES.values()),
                    'personas': {m: session['state'][m]['actor'] for m in MODES}}, cookie=new_cookie)
            if path == '/api/reset' and self.command == 'POST':
                session['state'] = new_sandbox()
                session['audit'] = []
                return self.reply(200, {'reset': True})
            if path == '/api/persona' and self.command == 'POST':
                actor = body.get('username')
                if set(body) != {'username'} or (actor is not None and (not isinstance(actor, str) or actor not in USERS)):
                    return self.reply(400, {'error': 'Unknown demo persona.'})
                for mode in MODES:
                    session['state'][mode]['actor'] = actor
                return self.reply(200, {'persona': actor})
            if path == '/api/audit' and self.command == 'GET':
                return self.reply(200, {'entries': session['audit'], 'limit': 200})
            parts = path.split('/', 3)
            if len(parts) != 4 or parts[2] not in MODES:
                return self.reply(404, {'error': 'Unknown lab operation.'})
            mode, resource = parts[2], parts[3]
            actor = session['state'][mode]['actor']
            status, response, reason = dispatch(session['state'], mode, self.command, resource, body)
            entry = {'mode': mode, 'actor': actor, 'method': self.command, 'resource': resource, 'status': status, 'reason': reason}
            session['audit'].append(entry)
            session['audit'] = session['audit'][-200:]
            return self.reply(status, {**response, '_decision': entry})


def main():
    port = int(os.environ.get('AUTH_LAB_PORT', '8820'))
    if not 1 <= port <= 65535:
        raise ValueError('AUTH_LAB_PORT must be 1..65535')
    with LabServer(('127.0.0.1', port)) as server:
        url = f'http://127.0.0.1:{server.server_port}'
        print(f'Authorization Testing Lab: {url}\nSynthetic local practice only. Ctrl+C stops the server.')
        if os.environ.get('AUTH_LAB_NO_BROWSER') != '1':
            webbrowser.open(url)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print('\nStopped.')


if __name__ == '__main__':
    main()
