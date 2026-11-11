#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""A fake RCS autoconfiguration server for the tests: HTTP and HTTPS on
localhost, one scenario per run. Logs every connection and request line to
--log so the test can count what imsroha-rcs sent. Never run it anywhere but
in the test's own network namespace."""
import argparse, http.server, os, ssl, sys, threading, urllib.parse

ap = argparse.ArgumentParser()
ap.add_argument('--http-port', type=int, required=True)
ap.add_argument('--https-port', type=int, required=True)
ap.add_argument('--cert', required=True)
ap.add_argument('--key', required=True)
ap.add_argument('--xml', required=True)
ap.add_argument('--scenario', required=True)
ap.add_argument('--log', required=True)
ap.add_argument('--events', help='a FIFO that gets "otp-cookie" when the OTP SMS is due')
a = ap.parse_args()

FULL = open(a.xml, 'rb').read()
log = open(a.log, 'a', buffering=1)
lock = threading.Lock()

def vers(v, d):
    return ('<?xml version="1.0"?>\n<wap-provisioningdoc version="1.1">\n'
            ' <characteristic type="VERS">\n'
            f'  <parm name="version" value="{v}"/>\n  <parm name="validity" value="{d}"/>\n'
            ' </characteristic>\n</wap-provisioningdoc>\n').encode()

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *args):
        pass
    def reply(self, code, body=b'', headers=()):
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        if body:
            self.send_header('Content-Type', 'text/xml')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True
    def do_GET(self):
        tls = isinstance(self.connection, ssl.SSLSocket)
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query, keep_blank_values=True)
        with lock:
            log.write(f"{'https' if tls else 'http'} {self.path}\n")
            for k, v in self.headers.items():
                log.write(f"  {k}: {v}\n")
        s = a.scenario
        cookie = self.headers.get('Cookie', '')
        if not tls:
            if s == 'otp':
                return self.reply(511)
            return self.reply(200, headers=[('Set-Cookie', 'up10=netauth; Path=/')])
        if 'OTP' in q:
            if q['OTP'] == ['654321'] and cookie == 'up10=otpcookie':
                return self.reply(200, FULL)
            return self.reply(403)
        if s == 'otp':
            if q.get('msisdn') == ['+821099999999'] and q.get('SMS_port') == ['37273']:
                self.reply(200, headers=[('Set-Cookie', 'up10=otpcookie')])
                # The test sends the OTP SMS now.
                if a.events:
                    with open(a.events, 'w') as ev:
                        ev.write('otp-cookie\n')
                return
            return self.reply(403)
        if cookie != 'up10=netauth':
            return self.reply(403)
        if s == 'netauth':
            if q.get('vers') == ['12']:
                return self.reply(200, vers(12, 2592000))
            return self.reply(200, FULL)
        if s == 'minus1':
            return self.reply(200, vers(-1, -1))
        if s == 'zero':
            return self.reply(200, vers(0, 0))
        if s == 'disable':
            return self.reply(200, vers(12, 2592000) if q.get('rcs_state') == ['-4'] else FULL)
        if s == '403':
            return self.reply(403)
        if s == '503':
            return self.reply(503, headers=[('Retry-After', '120')])
        return self.reply(500)

class S(http.server.ThreadingHTTPServer):
    address_family = __import__('socket').AF_INET
    def get_request(self):
        c, addr = super().get_request()
        with lock:
            log.write(f"connect {'https' if self.tls else 'http'}\n")
        return c, addr

h = S(('127.0.0.1', a.http_port), H); h.tls = False
t = S(('127.0.0.1', a.https_port), H); t.tls = True
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(a.cert, a.key)
t.socket = ctx.wrap_socket(t.socket, server_side=True)
for srv in (h, t):
    threading.Thread(target=srv.serve_forever, daemon=True).start()
print('ready', flush=True)
sys.stdin.read()
