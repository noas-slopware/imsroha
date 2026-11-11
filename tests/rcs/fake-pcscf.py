#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""A fake RCS network for the tests: P-CSCF/registrar (SIP over TLS) and an
MSRP relay (MSRP over TLS) on localhost. It challenges the REGISTER with
Digest and checks the answer, answers our chat INVITE and OPTIONS, takes the
message and sends the delivered IMDN, then (after our isComposing) opens a
chat to us from a second number and waits for our delivered and displayed
IMDNs. It prints "done" (or "FAIL ...") on stdout and logs every SIP and MSRP
message to --log. With --cs-port, the chat it opens also carries file-infos
(file transfer over HTTP) pointing at fake-cs.py there, and the file-infos
we send are kept in --ft-dir/mo-<n>.xml and answered with a delivered IMDN.
Never run it anywhere but in the test's own namespace."""
import argparse, hashlib, re, socket, ssl, sys, threading, time

ap = argparse.ArgumentParser()
ap.add_argument('--sip-port', type=int, required=True)
ap.add_argument('--msrp-port', type=int, required=True)
ap.add_argument('--cert', required=True)
ap.add_argument('--key', required=True)
ap.add_argument('--log', required=True)
ap.add_argument('--reg403', action='store_true', help='answer every authenticated REGISTER with 403')
ap.add_argument('--cs-port', type=int, help='fake-cs.py, for the file-infos we send')
ap.add_argument('--ft-dir', help='where the file-infos we receive are kept')
a = ap.parse_args()

USER, REALM, PWD = '+821099999999@rcs.test', 'rcs.test', 'testPassword'
NONCE = 'b5ba9c08f1a8e1d1'
log = open(a.log, 'a', buffering=1)
lock = threading.Lock()
state = {'sip': None, 'msg_ids': [], 'seen': set(), 'mo_files': 0}

def L(*x):
    with lock:
        log.write(' '.join(str(i) for i in x) + '\n')

def finish(msg):
    print(msg, flush=True)

def md5(s):
    return hashlib.md5(s.encode()).hexdigest()

def parse_sip(buf):
    while buf.startswith(b'\r\n'):
        buf = buf[2:]
    i = buf.find(b'\r\n\r\n')
    if i < 0:
        return None, buf
    head = buf[:i].decode()
    m = re.search(r'^Content-Length:\s*(\d+)', head, re.M | re.I)
    n = int(m.group(1)) if m else 0
    if len(buf) < i + 4 + n:
        return None, buf
    body = buf[i + 4:i + 4 + n].decode()
    lines = head.split('\r\n')
    hdrs = []
    for l in lines[1:]:
        k, _, v = l.partition(':')
        hdrs.append((k.strip(), v.strip()))
    return (lines[0], hdrs, body), buf[i + 4 + n:]

def h(hdrs, name):
    for k, v in hdrs:
        if k.lower() == name.lower():
            return v
    return None

def respond(conn, first, hdrs, code, reason, extra='', body='', ctype=None, totag='srv1'):
    out = [f'SIP/2.0 {code} {reason}']
    for k, v in hdrs:
        if k.lower() == 'via':
            out.append(f'Via: {v}')
    out.append(f'From: {h(hdrs, "From")}')
    to = h(hdrs, 'To')
    if ';tag=' not in to and code > 100:
        to += ';tag=' + totag
    out.append(f'To: {to}')
    out.append(f'Call-ID: {h(hdrs, "Call-ID")}')
    out.append(f'CSeq: {h(hdrs, "CSeq")}')
    if extra:
        out.extend(extra.rstrip('\r\n').split('\r\n'))
    if ctype:
        out.append(f'Content-Type: {ctype}')
    out.append(f'Content-Length: {len(body.encode())}')
    try:
        conn.sendall(('\r\n'.join(out) + '\r\n\r\n' + body).encode())
    except OSError:
        pass  # imsroha-rcs went away first (its de-registration at SIGTERM)

def sdp(path):
    return ('v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n'
            'm=message 12855 TCP/TLS/MSRP *\r\n'
            f'a=path:{path}\r\na=accept-types:message/cpim application/im-iscomposing+xml\r\n'
            'a=accept-wrapped-types:text/plain message/imdn+xml\r\na=setup:passive\r\na=sendrecv\r\n')

def check_auth(first, hdrs):
    auth = h(hdrs, 'Authorization') or ''
    p = dict(re.findall(r'(\w+)="?([^",]*)"?', auth))
    if p.get('nonce') != NONCE:
        return False
    ha1 = md5(f'{USER}:{REALM}:{PWD}')
    ha2 = md5(f'REGISTER:{p.get("uri")}')
    want = md5(f'{ha1}:{NONCE}:{p.get("nc")}:{p.get("cnonce")}:auth:{ha2}')
    return p.get('response') == want and p.get('username') == USER

def mt_invite():
    conn = state['sip']
    body = sdp(f'msrps://localhost:{a.msrp_port}/srv2;tcp')
    msg = (f'INVITE {state["contact"]} SIP/2.0\r\n'
           f'Via: SIP/2.0/TLS 127.0.0.1:{a.sip_port};branch=z9hG4bKmt1\r\n'
           'Max-Forwards: 69\r\n'
           'From: <tel:+821000000002>;tag=mtfrom\r\n'
           'To: <sip:+821099999999@rcs.test>\r\n'
           'Call-ID: mt-call-1\r\nCSeq: 1 INVITE\r\n'
           'P-Asserted-Identity: <tel:+821000000002>\r\n'
           f'Contact: <sip:peer2@localhost:{a.sip_port};transport=tls>;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"\r\n'
           'Conversation-ID: conv-mt\r\nContribution-ID: contrib-mt\r\n'
           'Content-Type: application/sdp\r\n'
           f'Content-Length: {len(body)}\r\n\r\n{body}')
    L('sip-out INVITE mt')
    conn.sendall(msg.encode())

def sip_conn(conn):
    state['sip'] = conn
    buf = b''
    while True:
        d = conn.recv(65536)
        if not d:
            L('sip closed')
            return
        buf += d
        while True:
            m, buf = parse_sip(buf)
            if not m:
                break
            first, hdrs, body = m
            L('sip-in', first)
            for k, v in hdrs:
                L('  ', f'{k}: {v}')
            if body:
                L('  body', body.replace('\r\n', '|'))
            meth = first.split(' ')[0]
            if meth == 'REGISTER':
                if h(hdrs, 'Expires') == '0':
                    respond(conn, first, hdrs, 200, 'OK')
                elif check_auth(first, hdrs) and a.reg403:
                    respond(conn, first, hdrs, 403, 'Forbidden')
                    L('event register-403')
                elif not check_auth(first, hdrs):
                    respond(conn, first, hdrs, 401, 'Unauthorized',
                            f'WWW-Authenticate: Digest realm="{REALM}",nonce="{NONCE}",qop="auth",opaque="op1",algorithm=MD5\r\n')
                else:
                    c = h(hdrs, 'Contact')
                    state['contact'] = re.search(r'<([^>]*)>', c).group(1)
                    respond(conn, first, hdrs, 200, 'OK',
                            f'Contact: {c};expires=600\r\nExpires: 600\r\n'
                            f'Service-Route: <sip:orig@localhost:{a.sip_port};transport=tls;lr>\r\n'
                            'P-Associated-URI: <sip:+821099999999@rcs.test>, <tel:+821099999999>\r\n')
                    L('event registered')
            elif meth == 'INVITE':
                respond(conn, first, hdrs, 100, 'Trying')
                respond(conn, first, hdrs, 200, 'OK',
                        f'Contact: <sip:peer1@localhost:{a.sip_port};transport=tls>\r\n'
                        f'Record-Route: <sip:rr@localhost:{a.sip_port};transport=tls;lr>\r\n',
                        sdp(f'msrps://localhost:{a.msrp_port}/srv1;tcp'), 'application/sdp')
            elif meth == 'PUBLISH':
                ok = 'org.openmobilealliance:ChatSession' in body or h(hdrs, 'Expires') == '0'
                respond(conn, first, hdrs, 200 if ok else 400, 'OK' if ok else 'Bad Request',
                        f'SIP-ETag: etag1\r\nExpires: {h(hdrs, "Expires")}\r\n')
                L('event publish', h(hdrs, 'Expires'), 'chat' if ok else 'no-chat')
            elif meth == 'SUBSCRIBE':
                respond(conn, first, hdrs, 200, 'OK', 'Expires: 0\r\n')
                if 'anonymous@anonymous.invalid' in (h(hdrs, 'From') or '') and h(hdrs, 'Privacy') == 'id':
                    L('event anonymous-fetch')
                pidf = ('<?xml version="1.0" encoding="UTF-8"?>\r\n<presence xmlns="urn:ietf:params:xml:ns:pidf" '
                        'xmlns:op="urn:oma:xml:prs:pidf:oma-pres" entity="tel:+821000000001">\r\n'
                        '<tuple id="a"><status><basic>open</basic></status><op:service-description>'
                        '<op:service-id>org.openmobilealliance:ChatSession</op:service-id><op:version>2.0</op:version>'
                        '</op:service-description><contact>tel:+821000000001</contact></tuple>\r\n</presence>\r\n')
                ftag = re.search(r'tag=([^;]+)', h(hdrs, 'From')).group(1)
                n = (f'NOTIFY {state["contact"]} SIP/2.0\r\n'
                     f'Via: SIP/2.0/TLS 127.0.0.1:{a.sip_port};branch=z9hG4bKnt1\r\n'
                     'Max-Forwards: 69\r\nFrom: <tel:+821000000001>;tag=nt1\r\n'
                     f'To: "Anonymous" <sip:anonymous@anonymous.invalid>;tag={ftag}\r\n'
                     f'Call-ID: {h(hdrs, "Call-ID")}\r\nCSeq: 1 NOTIFY\r\nEvent: presence\r\n'
                     'Subscription-State: terminated;reason=timeout\r\n'
                     'Content-Type: application/pidf+xml\r\n'
                     f'Content-Length: {len(pidf)}\r\n\r\n{pidf}')
                conn.sendall(n.encode())
            elif meth == 'OPTIONS':
                respond(conn, first, hdrs, 200, 'OK',
                        f'Contact: <sip:peer1@localhost:{a.sip_port}>;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"\r\n')
            elif meth in ('ACK',):
                pass
            elif meth in ('BYE', 'MESSAGE', 'UPDATE', 'CANCEL'):
                respond(conn, first, hdrs, 200, 'OK')
                if meth == 'MESSAGE':
                    imdn(body)
            elif first.startswith('SIP/2.0'):
                pass

def imdn(text):
    m = re.search(r'<message-id>([^<]*)</message-id>', text)
    s = re.search(r'<status><(\w+)/>', text)
    if m and s:
        L('event imdn', m.group(1), s.group(1))
        state['seen'].add((m.group(1), s.group(1)))
        if ('mt1', 'delivered') in state['seen'] and ('mt1', 'displayed') in state['seen']:
            finish('done')

def msrp_frames(buf):
    out = []
    while True:
        m = re.match(rb'MSRP (\S+) (\S+)[^\r\n]*\r\n', buf)
        if not m:
            return out, buf
        tid = m.group(1)
        end = re.search(rb'\r\n-------' + re.escape(tid) + rb'([$+#])\r\n', buf)
        if not end:
            return out, buf
        frame = buf[:end.end()]
        buf = buf[end.end():]
        head, _, body = frame[m.end():end.start() + 2].partition(b'\r\n\r\n')
        hdrs = {}
        for l in head.split(b'\r\n'):
            if b':' in l:
                k, _, v = l.partition(b':')
                hdrs[k.strip().decode().lower()] = v.strip().decode()
        body = body[:-2] if body.endswith(b'\r\n') else body
        out.append((tid.decode(), m.group(2).decode(), hdrs, body.decode(errors='replace')))

def msrp_send(conn, to, frm, ctype, body):
    with lock:
        state['tids'] = state.get('tids', 0) + 1
        tid = f't{int(time.time()*1000)%100000}x{state["tids"]}'
    b = body.encode()
    msg = (f'MSRP {tid} SEND\r\nTo-Path: {to}\r\nFrom-Path: {frm}\r\nMessage-ID: m{tid}\r\n'
           f'Byte-Range: 1-{len(b)}/{len(b)}\r\nContent-Type: {ctype}\r\n\r\n').encode() + b + f'\r\n-------{tid}$\r\n'.encode()
    conn.sendall(msg)

def cpim(msg_id, ctype, body, disp=None, extra=''):
    s = ('From: <sip:anonymous@anonymous.invalid>\r\nTo: <sip:anonymous@anonymous.invalid>\r\n'
         'DateTime: 2026-11-11T12:00:00.000Z\r\nNS: imdn <urn:ietf:params:imdn>\r\n'
         f'imdn.Message-ID: {msg_id}\r\n')
    if disp:
        s += f'imdn.Disposition-Notification: {disp}\r\n'
    return s + f'\r\nContent-Type: {ctype}\r\n{extra}Content-Length: {len(body.encode())}\r\n\r\n{body}'

def file_info(file_url, name, size, until='2066-08-23T04:53:50.000Z', thumb_url=None):
    x = ('<?xml version="1.0" encoding="UTF-8"?>\r\n<file xmlns="urn:gsma:params:xml:ns:rcs:rcs:fthttp" '
         'xmlns:e="urn:gsma:params:xml:ns:rcs:rcs:up:fthttpext">\r\n')
    if thumb_url:
        x += ('<file-info type="thumbnail">\r\n<file-size>3000</file-size>\r\n<content-type>image/png</content-type>\r\n'
              f'<data url="{thumb_url}" until="{until}"/>\r\n</file-info>\r\n')
    x += (f'<file-info type="file">\r\n<file-size>{size}</file-size>\r\n<file-name>{name}</file-name>\r\n'
          '<content-type>application/octet-stream</content-type>\r\n'
          f'<data url="{file_url}" until="{until}"/>\r\n</file-info>\r\n</file>\r\n')
    return x

def mt_files(conn, to, frm):
    cs = f'https://localhost:{a.cs_port}/content'
    FT = 'application/vnd.gsma.rcs-ft-http+xml;charset=UTF-8'
    D = 'positive-delivery, display'
    # A file with a thumbnail and a name that tries to leave the directory.
    msrp_send(conn, to, frm, 'message/cpim', cpim('mtft1', FT, file_info(
        f'{cs}/rx1?t=x&amp;s=40000', '..%2F..%2Fevil+name.bin', 40000, thumb_url=f'{cs}/rx1t'), D))
    # Expired: never fetched.
    msrp_send(conn, to, frm, 'message/cpim', cpim('mtft2', FT, file_info(
        f'{cs}/gone', 'old.bin', 10, until='2020-01-01T00:00:00.000Z'), D))
    # More than the configuration lets in: never fetched.
    msrp_send(conn, to, frm, 'message/cpim', cpim('mtft3', FT, file_info(f'{cs}/big', 'big.bin', 999999999), D))
    # Another host (127.0.0.1, not the configured localhost): its 401 gets no credentials.
    msrp_send(conn, to, frm, 'message/cpim', cpim('mtft4', FT, file_info(
        f'https://127.0.0.1:{a.cs_port}/content/rx4', 'x.bin', 100), D))
    L('event mt-files sent')

def mo_file(conn, to, frm, body):
    # CPIM headers, MIME headers, then the file-info exactly as it came.
    mid = re.search(r'imdn.Message-ID: (\S+)', body).group(1)
    xml = body.split('\r\n\r\n', 2)[2]
    state['mo_files'] += 1
    if a.ft_dir:
        open(f'{a.ft_dir}/mo-{state["mo_files"]}.xml', 'w', newline='').write(xml)
    L('event mo-file', state['mo_files'], mid)
    x = ('<?xml version="1.0" encoding="UTF-8"?>\r\n<imdn xmlns="urn:ietf:params:xml:ns:imdn">\r\n'
         f'<message-id>{mid}</message-id>\r\n<datetime>2026-11-11T12:00:01.000Z</datetime>\r\n'
         '<delivery-notification><status><delivered/></status></delivery-notification>\r\n</imdn>\r\n')
    msrp_send(conn, frm, to, 'message/cpim',
              cpim('imdnf' + str(state['mo_files']), 'message/imdn+xml', x, extra='Content-Disposition: notification\r\n'))

def msrp_conn(conn):
    buf = b''
    mine = None
    while True:
        d = conn.recv(65536)
        if not d:
            L('msrp closed')
            return
        buf += d
        frames, buf = msrp_frames(buf)
        for tid, what, hdrs, body in frames:
            L('msrp-in', tid, what, hdrs.get('to-path'), hdrs.get('content-type'), body.replace('\r\n', '|'))
            if what != 'SEND':
                continue
            to, frm = hdrs.get('to-path', ''), hdrs.get('from-path', '')
            mine = to
            if hdrs.get('failure-report', 'yes') != 'no':
                conn.sendall(f'MSRP {tid} 200 OK\r\nTo-Path: {frm}\r\nFrom-Path: {to}\r\n-------{tid}$\r\n'.encode())
            if not body:
                if 'srv2' in to:
                    # Our chat to them: the message, asking for both IMDNs.
                    msrp_send(conn, frm, to, 'message/cpim',
                              cpim('mt1', 'text/plain', 'hi from 2', 'positive-delivery, display'))
                    if a.cs_port:
                        mt_files(conn, frm, to)
                continue
            if 'rcs-ft-http+xml' in body and 'imdn+xml' not in body:
                mo_file(conn, to, frm, body)
                continue
            if 'hello' in body and 'text/plain' in body:
                mid = re.search(r'imdn.Message-ID: (\S+)', body).group(1)
                L('event mo-message', mid)
                xml = ('<?xml version="1.0" encoding="UTF-8"?>\r\n<imdn xmlns="urn:ietf:params:xml:ns:imdn">\r\n'
                       f'<message-id>{mid}</message-id>\r\n<datetime>2026-11-11T12:00:01.000Z</datetime>\r\n'
                       '<delivery-notification><status><delivered/></status></delivery-notification>\r\n</imdn>\r\n')
                msrp_send(conn, frm, to, 'message/cpim',
                          cpim('imdn1', 'message/imdn+xml', xml, extra='Content-Disposition: notification\r\n'))
            elif 'isComposing' in body:
                L('event composing', 'active' if '<state>active' in body else 'idle',
                  'cpim' if hdrs.get('content-type') == 'message/cpim' else 'bare')
                mt_invite()
            elif 'imdn+xml' in body:
                imdn(body)

def serve(port, handler, ctx):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', port))
    s.listen(8)
    def loop():
        while True:
            c, _ = s.accept()
            try:
                t = ctx.wrap_socket(c, server_side=True)
            except Exception as e:
                L('tls failed', e)
                continue
            L('connect', port)
            threading.Thread(target=handler, args=(t,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(a.cert, a.key)
serve(a.sip_port, sip_conn, ctx)
serve(a.msrp_port, msrp_conn, ctx)
print('ready', flush=True)
sys.stdin.read()
