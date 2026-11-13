#!/usr/bin/env python3
"""An ALPN change must never bypass configured HTTP/1 module policies.

Requires make mod, make certs, and the Python h2 package.
"""
import base64
import hashlib
import hmac
import json
from pathlib import Path
import socket
import ssl
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'compat'))
from harness import Server, HTTPS_PORT, ROOT
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import ResponseReceived


def status(protocols, token=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(protocols)
    with ctx.wrap_socket(socket.create_connection(('127.0.0.1', HTTPS_PORT), 3),
                         server_hostname='localhost') as s:
        s.settimeout(3)
        proto = s.selected_alpn_protocol()
        if proto == 'h2':
            c = H2Connection(config=H2Configuration(client_side=True, header_encoding='utf-8'))
            c.initiate_connection()
            headers = [(':method', 'GET'), (':scheme', 'https'),
                       (':authority', 'localhost'), (':path', '/ok.txt')]
            if token:
                headers.append(('authorization', 'Bearer ' + token))
            c.send_headers(1, headers, end_stream=True)
            s.sendall(c.data_to_send())
            while True:
                data = s.recv(65536)
                if not data:
                    raise AssertionError('no HTTP/2 response')
                for event in c.receive_data(data):
                    if isinstance(event, ResponseReceived):
                        return proto, int(dict(event.headers)[':status'])
                s.sendall(c.data_to_send())
        auth = f'Authorization: Bearer {token}\r\n' if token else ''
        s.sendall(f'GET /ok.txt HTTP/1.1\r\nHost: localhost\r\n{auth}Connection: close\r\n\r\n'.encode())
        data = b''
        while b'\r\n' not in data:
            part = s.recv(4096)
            if not part:
                raise AssertionError('no HTTP/1.1 response')
            data += part
        return proto, int(data.split()[1])


def main():
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=')
    claims = b64(json.dumps({'iss': 'syzygy'}).encode())
    signed = b64(b'{"alg":"HS256","typ":"JWT"}') + b'.' + claims
    token = (signed + b'.' + b64(hmac.new(b'secret', signed, hashlib.sha256).digest())).decode()
    server = Server(extra=['-M', str(Path(ROOT) / 'modules/jwt_auth.so') +
                           ':secret_hex=736563726574,iss=syzygy'])
    failures = 0
    try:
        server.start()
        for protocols, credential, expected in [(['http/1.1'], None, 401),
                                                (['h2', 'http/1.1'], None, 401),
                                                (['h2'], None, None),
                                                (['h2', 'http/1.1'], token, 200)]:
            try:
                proto, code = status(protocols, credential)
                ok = code == expected
            except ssl.SSLError as e:
                if expected is not None or e.reason != 'TLSV1_ALERT_NO_APPLICATION_PROTOCOL':
                    raise
                proto, code, ok = 'rejected', None, True
            print(f'{"PASS" if ok else "FAIL"} ALPN={protocols} negotiated={proto} status={code} expected={expected}')
            failures += not ok
    finally:
        server.stop()
    return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())
