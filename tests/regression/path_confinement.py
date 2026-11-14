#!/usr/bin/env python3
"""Static files must not escape the document root over HTTP/1.1 or HTTP/2.

Requires the built server, make certs, and the h2 Python package.
All fixtures and server processes are local and cleaned up on exit.
"""
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import tempfile
import time

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, ResponseReceived, StreamEnded

ROOT = Path(__file__).resolve().parents[2]


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def request(p, path, h2=False):
    with socket.create_connection(('127.0.0.1', p), 3) as tcp:
        tcp.settimeout(3)
        if not h2:
            tcp.sendall(f'GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'.encode())
            data = b''
            while True:
                chunk = tcp.recv(65536)
                if not chunk:
                    break
                data += chunk
            headers, body = data.split(b'\r\n\r\n', 1)
            return int(headers.split()[1]), body
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(['h2'])
        with ctx.wrap_socket(tcp, server_hostname='localhost') as tls:
            c = H2Connection(config=H2Configuration(client_side=True, header_encoding='utf-8'))
            c.initiate_connection()
            c.send_headers(1, [(':method', 'GET'), (':scheme', 'https'),
                               (':authority', 'localhost'), (':path', path)], end_stream=True)
            tls.sendall(c.data_to_send())
            status, body = None, b''
            while True:
                data = tls.recv(65536)
                if not data:
                    raise AssertionError('connection closed before END_STREAM')
                for e in c.receive_data(data):
                    if isinstance(e, ResponseReceived):
                        status = int(dict(e.headers)[':status'])
                    elif isinstance(e, DataReceived):
                        body += e.data
                        c.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
                    elif isinstance(e, StreamEnded):
                        return status, body
                tls.sendall(c.data_to_send())


def main():
    failures = []
    with tempfile.TemporaryDirectory(prefix='syzygy-path-') as tmp:
        base = Path(tmp)
        www, outside = base / 'www', base / 'outside'
        www.mkdir()
        outside.mkdir()
        (outside / 'secret.txt').write_text('OUTSIDE SECRET')
        (outside / 'index.html').write_text('OUTSIDE SECRET')
        (www / 'ok.txt').write_text('inside')
        (www / 'sub').mkdir()
        (www / 'sub' / 'index.html').write_text('inside index')
        (www / 'escape').symlink_to(outside, target_is_directory=True)
        (www / 'leaf').symlink_to(outside / 'secret.txt')
        (www / 'indexlink').mkdir()
        (www / 'indexlink' / 'index.html').symlink_to(outside / 'index.html')
        hp, tp = port(), port()
        while tp == hp:
            tp = port()
        with (base / 'server.log').open('w') as log:
            proc = subprocess.Popen([str(ROOT / 'syzygy'), '-p', str(hp), '-T', str(tp),
                                     '-C', str(ROOT / 'certs/cert.pem'),
                                     '-K', str(ROOT / 'certs/key.pem'), '-r', str(www), '-w', '1'],
                                    stdout=log, stderr=log, start_new_session=True)
            try:
                for _ in range(100):
                    if proc.poll() is not None:
                        raise RuntimeError((base / 'server.log').read_text())
                    try:
                        with socket.create_connection(('127.0.0.1', hp), .1):
                            break
                    except OSError:
                        time.sleep(.05)
                for h2 in (False, True):
                    for path, expected in [('/ok.txt', 200), ('/sub/', 200),
                                           ('/escape/secret.txt', 404), ('/escape/', 404),
                                           ('/leaf', 404), ('/indexlink/', 403)]:
                        status, body = request(tp if h2 else hp, path, h2)
                        ok = status == expected and b'OUTSIDE SECRET' not in body
                        label = f'{"h2" if h2 else "h1"} {path}: {status} (expected {expected})'
                        print(('PASS ' if ok else 'FAIL ') + label)
                        if not ok:
                            failures.append(label)
            finally:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
    return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())
