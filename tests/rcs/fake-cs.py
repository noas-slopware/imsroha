#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""A fake RCS content server (file transfer over HTTP, as stock's UploadFileTask and DownloadFileTask talk to it) for the
tests, HTTPS on localhost. Every request needs HTTP Digest (MD5, qop=auth)
with --user/--pwd: an empty POST and a GET without it get a 401. A POST with
multipart/form-data (tid, File) stores the file as <store>/up-<n>.bin,
answers with a file-info whose data URL serves it back, and keeps that answer
in <store>/up-<n>.xml. --serve NAME=PATH serves PATH at /content/NAME;
--chunked NAME sends it with chunked transfer coding. Everything goes to
--log. Never run it anywhere but in the test's own namespace."""
import argparse, hashlib, re, socket, ssl, sys, threading

ap = argparse.ArgumentParser()
ap.add_argument('--port', type=int, required=True)
ap.add_argument('--cert', required=True)
ap.add_argument('--key', required=True)
ap.add_argument('--log', required=True)
ap.add_argument('--store', required=True)
ap.add_argument('--user', required=True)
ap.add_argument('--pwd', required=True)
ap.add_argument('--serve', action='append', default=[])
ap.add_argument('--chunked', action='append', default=[])
a = ap.parse_args()

REALM, NONCE = 'cs.test', 'ftnonce0123456789'
log = open(a.log, 'a', buffering=1)
lock = threading.Lock()
files = dict(s.split('=', 1) for s in a.serve)
uploads = [0]

def L(*x):
    with lock:
        log.write(' '.join(str(i) for i in x) + '\n')

def md5(s):
    return hashlib.md5(s.encode()).hexdigest()

def authorized(method, path, hdrs):
    auth = hdrs.get('authorization', '')
    if not auth.startswith('Digest '):
        return False
    p = dict(re.findall(r'(\w+)="?([^",]*)"?', auth))
    ha1 = md5(f'{a.user}:{REALM}:{a.pwd}')
    ha2 = md5(f'{method}:{p.get("uri")}')
    want = md5(f'{ha1}:{NONCE}:{p.get("nc")}:{p.get("cnonce")}:auth:{ha2}')
    ok = (p.get('username') == a.user and p.get('nonce') == NONCE and p.get('uri') == path
          and p.get('qop') == 'auth' and p.get('response') == want)
    if not ok:
        L('event bad-auth', method, path)
    return ok

def send(conn, code, reason, body=b'', ctype=None, extra='', chunked=False):
    h = [f'HTTP/1.1 {code} {reason}', 'Connection: close']
    if ctype:
        h.append(f'Content-Type: {ctype}')
    if extra:
        h.append(extra)
    if chunked:
        h.append('Transfer-Encoding: chunked')
        out = ('\r\n'.join(h) + '\r\n\r\n').encode()
        # Odd-sized chunks with an extension, then a trailer.
        i, n = 0, 1
        while i < len(body):
            part = body[i:i + 997 * n]
            out += f'{len(part):x};x=y\r\n'.encode() + part + b'\r\n'
            i += len(part)
            n += 1
        out += b'0\r\nX-Trailer: 1\r\n\r\n'
    else:
        h.append(f'Content-Length: {len(body)}')
        out = ('\r\n'.join(h) + '\r\n\r\n').encode() + body
    conn.sendall(out)

def challenge(conn):
    send(conn, 401, 'Unauthorized',
         extra=f'WWW-Authenticate: Digest realm="{REALM}",nonce="{NONCE}",qop="auth",algorithm=MD5')

def multipart(ctype, body):
    m = re.search(r'boundary=([^;]+)', ctype or '')
    if not m:
        return None
    b = b'--' + m.group(1).strip('"').encode()
    parts = {}
    for chunk in body.split(b)[1:]:
        if chunk.startswith(b'--'):
            break
        head, _, data = chunk[2:].partition(b'\r\n\r\n')
        data = data[:-2] if data.endswith(b'\r\n') else data
        hd = head.decode()
        name = re.search(r'name="([^"]*)"', hd)
        fname = re.search(r'filename="([^"]*)"', hd)
        ct = re.search(r'Content-Type: (\S+)', hd)
        if name:
            parts[name.group(1)] = (fname.group(1) if fname else None, ct.group(1) if ct else None, data)
    return parts

def handle(conn):
    buf = b''
    while b'\r\n\r\n' not in buf:
        d = conn.recv(65536)
        if not d:
            return
        buf += d
    head, _, body = buf.partition(b'\r\n\r\n')
    lines = head.decode().split('\r\n')
    method, path, _ = lines[0].split(' ', 2)
    hdrs = {}
    for l in lines[1:]:
        k, _, v = l.partition(':')
        hdrs[k.strip().lower()] = v.strip()
    n = int(hdrs.get('content-length', '0'))
    while len(body) < n:
        d = conn.recv(65536)
        if not d:
            break
        body += d
    L('request', method, path, 'len', n, 'auth' if 'authorization' in hdrs else 'noauth',
      'ua', hdrs.get('user-agent'))
    if method == 'POST' and n == 0:
        L('event empty-post', path)
        if authorized(method, path, hdrs):
            send(conn, 204, 'No Content')
        else:
            challenge(conn)
        return
    if not authorized(method, path, hdrs):
        L('event 401', method, path)
        challenge(conn)
        return
    if method == 'POST':
        parts = multipart(hdrs.get('content-type'), body)
        if not parts or 'tid' not in parts or 'File' not in parts:
            L('event bad-upload', path)
            send(conn, 400, 'Bad Request')
            return
        names = list(parts)
        with lock:
            uploads[0] += 1
            k = uploads[0]
        fname, fct, data = parts['File']
        open(f'{a.store}/up-{k}.bin', 'wb').write(data)
        L('event upload', path, k, 'tid', parts['tid'][2].decode(), 'parts', ','.join(names),
          'name', fname, 'ctype', fct, 'size', len(data))
        files[f'dl-{k}'] = f'{a.store}/up-{k}.bin'
        xml = ('<?xml version="1.0" encoding="UTF-8"?>\r\n'
               '<file xmlns="urn:gsma:params:xml:ns:rcs:rcs:fthttp">\r\n'
               f'<file-info type="file">\r\n<file-size>{len(data)}</file-size>\r\n'
               f'<file-name>{fname}</file-name>\r\n<content-type>{fct}</content-type>\r\n'
               f'<data url="https://localhost:{a.port}/content/dl-{k}?s={len(data)}&amp;k={k}" '
               'until="2066-08-23T04:53:50.000Z"/>\r\n</file-info>\r\n</file>\r\n').encode()
        open(f'{a.store}/up-{k}.xml', 'wb').write(xml)
        send(conn, 200, 'OK', xml, 'application/vnd.gsma.rcs-ft-http+xml')
        return
    if method == 'GET':
        name = path.split('?')[0].rsplit('/', 1)[-1]
        if name not in files:
            L('event get-404', name)
            send(conn, 404, 'Not Found')
            return
        L('event get', name)
        send(conn, 200, 'OK', open(files[name], 'rb').read(), 'application/octet-stream',
             chunked=name in a.chunked)
        return
    send(conn, 405, 'Method Not Allowed')

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(a.cert, a.key)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', a.port))
s.listen(8)

def one(c):
    try:
        t = ctx.wrap_socket(c, server_side=True)
    except Exception as e:
        L('tls failed', e)
        return
    try:
        handle(t)
    except Exception as e:
        L('error', repr(e))
    finally:
        try:
            t.close()
        except OSError:
            pass

print('ready', flush=True)
sys.stdout.close()
while True:
    c, _ = s.accept()
    threading.Thread(target=one, args=(c,), daemon=True).start()
