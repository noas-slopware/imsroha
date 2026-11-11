#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""A fake botinfo server for the tests (RCC.07 3.6.4.1.1, R9 7.7.3.2):
HTTPS on localhost, GET /bot?id=...&hl=...&ho=...&v=...
  sip:bot@botplatform.test   200, ETag "b1", Cache-Control: max-age=3600
  sip:bot2@botplatform.test  200, ETag "b2", Cache-Control: no-cache; 304 to If-None-Match "b2"
  anything else              404
Logs every request line and If-None-Match to --log. Never run it anywhere
but in the test's own network namespace."""
import argparse, http.server, ssl, sys, threading, urllib.parse

ap = argparse.ArgumentParser()
ap.add_argument('--port', type=int, required=True)
ap.add_argument('--cert', required=True)
ap.add_argument('--key', required=True)
ap.add_argument('--log', required=True)
ap.add_argument('--dir', required=True, help='botinfo-bot.json, botinfo-bot2.json')
a = ap.parse_args()

log = open(a.log, 'a', buffering=1)
BOTS = {
    'sip:bot@botplatform.test': ('botinfo-bot.json', '"b1"', 'max-age=3600'),
    'sip:bot2@botplatform.test': ('botinfo-bot2.json', '"b2"', 'no-cache'),
}

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *args):
        pass
    def reply(self, code, body=b'', headers=()):
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        inm = self.headers.get('If-None-Match')
        log.write(f'request {self.path} inm {inm} ua {self.headers.get("User-Agent")}\n')
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(u.query)
        bot = BOTS.get(q.get('id', [''])[0]) if u.path == '/bot' else None
        if not bot:
            self.reply(404)
            return
        name, etag, cc = bot
        if inm == etag:
            self.reply(304, headers=(('ETag', etag), ('Cache-Control', cc)))
            return
        body = open(f'{a.dir}/{name}', 'rb').read()
        self.reply(200, body, (('Content-Type', 'application/json'), ('ETag', etag), ('Cache-Control', cc)))

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(a.cert, a.key)
srv = http.server.ThreadingHTTPServer(('127.0.0.1', a.port), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
threading.Thread(target=srv.serve_forever, daemon=True).start()
print('ready', flush=True)
sys.stdin.read()
