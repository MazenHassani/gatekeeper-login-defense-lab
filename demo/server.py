"""Loopback-only dashboard with strict origin/host checks and bounded experiments."""
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import json
from lab import experiment

HOST, PORT = '127.0.0.1', 8765
ORIGIN = f'http://{HOST}:{PORT}'
ROOT = Path(__file__).parent / 'static'

class Handler(BaseHTTPRequestHandler):
    def send(self, code, payload, content_type='application/json'):
        data = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(data)

    def valid_host(self):
        return self.headers.get('Host') == f'{HOST}:{PORT}'

    def do_GET(self):
        if not self.valid_host():
            return self.send(403, {'error': 'Loopback host required'})
        routes = {'/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'text/javascript'), '/style.css': ('style.css', 'text/css')}
        if self.path not in routes:
            return self.send(404, {'error': 'Not found'})
        name, mime = routes[self.path]
        self.send(200, (ROOT / name).read_text(), mime)

    def do_POST(self):
        if not self.valid_host() or self.headers.get('Origin') != ORIGIN:
            return self.send(403, {'error': 'Same-origin loopback requests only'})
        if self.path != '/api/experiment':
            return self.send(404, {'error': 'Not found'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 1 <= length <= 512:
                raise ValueError('Body must be 1–512 bytes')
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict) or set(body) - {'scenario', 'count', 'seed'}:
                raise ValueError('Only scenario, count and seed are accepted')
            result = experiment(**body)
        except (ValueError, TypeError) as exc:
            return self.send(400, {'error': str(exc)})
        self.send(200, result)

if __name__ == '__main__':
    print(f'Gatekeeper Lab → {ORIGIN}', flush=True)
    HTTPServer((HOST, PORT), Handler).serve_forever()
