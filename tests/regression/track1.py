#!/usr/bin/env python3
############################################################################
#                                                                          #
#   ____ ___  _ ____ ___  _ ________  _                                    #
#  / ___\\  \///_   \\  \///  __/\  \//                                    #
#  |    \ \  /  /   / \  / | |  _ \  /                                     #
#  \___ | / /  /   /_ / /  | |_// / /                                      #
#  \____//_/   \____//_/   \____\/_/                                       #
#                                                                          #
#  Syzygy                                                                  #
#                                                                          #
#  Created by Hamza Bensliman <benslimanh> for 2026                        #
#                                                                          #
#  This software is licensed under the terms of the MIT license.           #
#  You may use, copy, modify, merge, publish, distribute and/or sell       #
#  copies of the Software, and permit persons to whom the Software is      #
#  furnished to do so, under the terms of the MIT license.                 #
#                                                                          #
#  This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF   #
#  ANY KIND, either express or implied.                                    #
#                                                                          #
############################################################################

"""
track1.py - regression tests for Track 1 (vulnerability remediation).

Every case here was written against commit af9f0ea *before* the corresponding
fix, and fails there. Each case therefore doubles as:

  * a proof that the defect is real and reachable from the network, and
  * the acceptance test for the fix that closes it.

The suite is deliberately independent of pytest and of any test framework:
it speaks raw TCP/TLS so that a failure cannot be masked by a client library
being lenient.

Usage:
    python3 tests/regression/track1.py                 # run all
    python3 tests/regression/track1.py --only T1-S03   # substring filter
    python3 tests/regression/track1.py --out /tmp/t1.json

Exit status is 0 only when every selected case passes.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
import traceback
from dataclasses import asdict, dataclass

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BIN = os.path.join(ROOT, "syzygy")
CERT = os.path.join(ROOT, "certs", "cert.pem")
KEY = os.path.join(ROOT, "certs", "key.pem")
WWW = os.path.join(ROOT, "tests", "compat", "fixtures")
LOG = "/tmp/syzygy-track1.log"

HTTP_PORT = 18090
HTTPS_PORT = 18490
UPSTREAM_PORT = 19999
TOKEN = "track1-admin-token"


class Fail(AssertionError):
    pass


def check(cond, msg):
    if not cond:
        raise Fail(msg)


# --------------------------------------------------------------------------- #
# server profiles
# --------------------------------------------------------------------------- #
_NEXT_BASE = [HTTP_PORT]


class Server:
    """A syzygy instance with an explicit argument vector.

    Every profile gets its own port pair; otherwise a second profile would
    silently talk to the first one's socket (this bit the suite once already).
    """

    def __init__(self, name: str, extra: list[str] | None = None, admin: bool = True,
                 with_tls: bool = True):
        self.name = name
        self.extra = extra or []
        self.admin = admin
        self.with_tls = with_tls
        self.proc: subprocess.Popen | None = None
        self.http = _NEXT_BASE[0]
        self.https = _NEXT_BASE[0] + 400
        _NEXT_BASE[0] += 10

    def args(self) -> list[str]:
        a = [BIN, "-p", str(self.http), "-r", WWW, "-w", "2", "-l", LOG]
        if self.with_tls:
            a += ["-T", str(self.https), "-C", CERT, "-K", KEY, "-3"]
        else:
            a += ["-T", "0"]
        if self.admin:
            a += ["-A", TOKEN]
        return a + self.extra

    def start(self):
        self.proc = subprocess.Popen(self.args(), cwd=ROOT, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, start_new_session=True)
        ok = wait_port(self.http, 8.0) and (not self.with_tls or wait_port(self.https, 8.0))
        if not ok:
            out = b""
            if self.proc.poll() is not None and self.proc.stdout:
                out = self.proc.stdout.read() or b""
            self.stop()
            raise RuntimeError(f"[{self.name}] server did not start: "
                               f"{out.decode(errors='replace')[:400]}")
        return self

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(os.getpgid(self.proc.pid), 15)
            except OSError:
                pass
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(self.proc.pid), 9)
                except OSError:
                    pass


PROFILES: dict[str, dict] = {
    "default": {},
    "no_admin_token": {"admin": False},
    "short_timeouts": {"extra": ["--header-timeout", "2", "--idle-timeout", "2",
                                 "--write-timeout", "2"]},
    "proxy": {"extra": ["-P", f"127.0.0.1:{UPSTREAM_PORT}"]},
}

_PROFILES: dict[str, Server] = {}
_CURRENT: dict[str, Server | None] = {"srv": None}


def profile(name: str = "default") -> Server:
    """Lazily start (and cache) one server per configuration profile."""
    if name not in _PROFILES:
        _PROFILES[name] = Server(name, **PROFILES.get(name, {})).start()
    return _PROFILES[name]


def shutdown_profiles():
    for s in _PROFILES.values():
        s.stop()
    _PROFILES.clear()


def wait_port(port: int, timeout: float) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.25).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


# --------------------------------------------------------------------------- #
# wire helpers
# --------------------------------------------------------------------------- #
def connect(port: int | None = None, timeout: float = 3.0) -> socket.socket:
    if port is None:
        port = _CURRENT["srv"].http if _CURRENT["srv"] else HTTP_PORT
    s = socket.create_connection(("127.0.0.1", port), timeout)
    s.settimeout(timeout)
    return s


def read_all(s: socket.socket, idle: float = 0.35, hard: float = 3.0) -> bytes:
    """Read until EOF, error, or `idle` seconds of silence."""
    chunks, end, idle_end = [], time.time() + hard, time.time() + idle
    while time.time() < end:
        if time.time() > idle_end:
            break
        try:
            b = s.recv(65536)
        except (socket.timeout, TimeoutError):
            break
        except ConnectionResetError:
            chunks.append(b"<<RST>>")
            break
        if not b:
            break
        chunks.append(b)
        idle_end = time.time() + idle
    return b"".join(chunks)


def exchange(payload: bytes, port: int | None = None, tls: bool = False,
             idle: float = 0.35, hard: float = 3.0, alpn=None) -> bytes:
    if port is None:
        port = _CURRENT["srv"].http if _CURRENT["srv"] else HTTP_PORT
    s = None
    try:
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if alpn:
                ctx.set_alpn_protocols(alpn)
            s = ctx.wrap_socket(connect(port), server_hostname="localhost")
        else:
            s = connect(port)
        s.sendall(payload)
        return read_all(s, idle=idle, hard=hard)
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass


def parse(buf: bytes):
    """(status, headers, body) of the first response, or (None, {}, b'') ."""
    if not buf:
        return None, {}, b""
    head, _, body = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    parts = lines[0].split(b" ")
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/"):
        return None, {}, body
    try:
        status = int(parts[1])
    except ValueError:
        return None, {}, body
    hdrs = {}
    for ln in lines[1:]:
        if b":" in ln:
            k, _, v = ln.partition(b":")
            hdrs[k.strip().lower().decode(errors="replace")] = v.strip().decode(errors="replace")
    return status, hdrs, body


def req(path: str = "/ok.txt", headers: str = "", version: str = "HTTP/1.1") -> bytes:
    return (f"GET {path} {version}\r\nHost: localhost\r\n{headers}\r\n").encode()


def closes_within(sock: socket.socket, seconds: float) -> tuple[bool, float]:
    """Did the peer close (EOF/RST) within `seconds`? Returns (closed, elapsed)."""
    t0 = time.time()
    sock.settimeout(seconds)
    try:
        while True:
            b = sock.recv(65536)
            if not b:
                return True, time.time() - t0
    except ConnectionResetError:
        return True, time.time() - t0
    except (socket.timeout, TimeoutError):
        return False, time.time() - t0


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #
@dataclass
class Result:
    id: str
    name: str
    defect: str
    status: str = "skip"
    detail: str = ""
    trace: str = ""


REGISTRY: list[tuple[str, str, str, str, callable]] = []


def case(cid: str, name: str, defect: str, prof: str = "default"):
    """Register a case. `prof` selects which server configuration it needs."""
    def deco(fn):
        def runner():
            _CURRENT["srv"] = profile(prof)
            return fn(_CURRENT["srv"])
        REGISTRY.append((cid, name, defect, prof, runner))
        return runner
    return deco


# --------------------------------------------------------------------------- #
# S-01 - stack over-read in the reverse proxy
# --------------------------------------------------------------------------- #
class _Upstream(threading.Thread):
    """Records exactly what the proxy sent, then answers 200 with a short body."""

    def __init__(self):
        super().__init__(daemon=True)
        self.received = b""
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", UPSTREAM_PORT))
        self.srv.listen(8)

    def run(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(1.0)
                data = b""
                try:
                    while b"\r\n\r\n" not in data and len(data) < 65536:
                        b = conn.recv(65536)
                        if not b:
                            break
                        data += b
                    if data.startswith(b"GET /_"):
                        # keep the socket open a moment: if the proxy over-read
                        # its buffer the spilled bytes arrive right after the
                        # header terminator
                        deadline = time.time() + 0.4
                        while time.time() < deadline and len(data) < 65536:
                            try:
                                b = conn.recv(65536)
                            except (socket.timeout, TimeoutError):
                                break
                            if not b:
                                break
                            data += b
                except (socket.timeout, TimeoutError):
                    pass
                # syzygy health-checks every upstream every 2 s; only keep the
                # request we care about, but answer health checks immediately
                # (a slow answer marks the upstream unhealthy and opens the
                # circuit breaker).
                if data.startswith(b"GET /_"):
                    self.received = data
                try:
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                                 b"Connection: close\r\n\r\nok")
                except OSError:
                    pass


@case("T1-S01", "reverse proxy sends only the request it built (no stack bytes)",
      "S-01 stack buffer over-read, src/proxy.c:342", prof="proxy")
def t_s01(srv):
    up = _Upstream()
    up.start()
    time.sleep(0.5)          # let the listener bind before syzygy health-checks it
    try:
        check(srv.alive(), "proxy server died")
        # 3000-char path: the path fits in SYZYGY_MAX_URI (8192) but the
        # 2048-byte stack buffer in proxy_do() cannot hold request + headers.
        path = "/_" + "A" * 3000
        status = None
        for _ in range(6):
            got = exchange(req(path), idle=0.6, hard=4.0)
            status, _, _ = parse(got)
            if status == 200:
                break
            time.sleep(0.5)      # circuit breaker half-opens after cb_recovery_ms
        check(status == 200, f"proxy did not answer 200 (got {status!r}; "
                             f"is the upstream reachable?)")
        data = up.received
        check(data, "upstream received nothing")
        check(data.endswith(b"\r\n\r\n"),
              f"upstream received {len(data)} bytes and they do NOT end at the "
              f"header terminator: the proxy wrote past its 2048-byte buffer "
              f"(tail={data[-40:]!r})")
        check(b"\x00" not in data, "upstream received NUL bytes (uninitialised stack)")
        expected = len(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{UPSTREAM_PORT}\r\n"
                       f"Connection: close\r\nAccept: */*\r\n"
                       f"User-Agent: syzygy/0.1.0\r\n\r\n")
        check(len(data) == expected,
              f"upstream saw {len(data)} bytes, a correctly-built request is {expected}")
    finally:
        try:
            up.srv.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# S-14 - access-log line is written with snprintf()'s would-be length
# --------------------------------------------------------------------------- #
@case("T1-S14", "access log never records more bytes than the line buffer holds",
      "S-14 unchecked snprintf return -> stack over-read into the log, src/log.c:157")
def t_s14(srv):
    marker = "/_" + "L" * 2900 + f"{os.getpid():x}"
    st, _, _ = parse(exchange(req(marker), idle=0.4, hard=3.0))
    check(st is not None, "no response to the long-URI probe")
    time.sleep(0.6)          # access log is written through a ring buffer
    with open(LOG, "rb") as f:
        lines = f.read().split(b"\n")
    hit = [ln for ln in lines if marker[:40].encode() in ln]
    check(hit, "the probe request never reached the access log")
    ln = hit[-1]
    check(len(ln) <= 1024,
          f"access-log line is {len(ln)} bytes; log_emit() writes at most 1023")
    bad = [b for b in ln if b < 0x20 or b > 0x7e]
    check(not bad,
          f"access-log line contains {len(bad)} non-printable byte(s) "
          f"({bad[:8]!r}): stack memory is being copied into the log")


# --------------------------------------------------------------------------- #
# S-02 - admin API reachable without a token when none is configured
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# S-13 - ETag synthesis
# --------------------------------------------------------------------------- #
@case("T1-S13", "ETag is well formed and If-None-Match yields 304",
      "S-13 uninitialised ETag buffer, src/response.c:238")
def t_s13(srv):
    st, hdrs, _ = parse(exchange(req("/payload_5k.bin")))
    check(st == 200, f"GET /payload_5k.bin returned {st}")
    etag = hdrs.get("etag", "")
    check(etag, "static response carries no ETag")
    check(len(etag) >= 2 and etag.startswith('"') and etag.endswith('"'),
          f"ETag {etag!r} is not a quoted string")
    check(all(0x20 <= ord(ch) < 0x7f for ch in etag),
          f"ETag {etag!r} contains non-printable bytes (uninitialised stack)")
    st2, _, body2 = parse(exchange(req("/payload_5k.bin", f"If-None-Match: {etag}\r\n")))
    check(st2 == 304, f"If-None-Match with the served ETag returned {st2}, expected 304")
    check(body2 == b"", "the 304 response carried a body")


@case("T1-S02a", "admin API is closed when no token is configured",
      "S-02 admin API fails open, src/admin.c:64-68", prof="no_admin_token")
def t_s02a(srv):
    check(srv.alive(), "server died")
    for path in ("/_admin/health", "/_admin/config", "/_admin/dashboard"):
        got = exchange(req(path))
        status, _, body = parse(got)
        check(status is not None, f"{path}: no response at all")
        check(status in (401, 403, 404),
              f"{path} returned {status} with no admin token configured "
              f"(body={body[:80]!r}); an unauthenticated caller reached the "
              f"control plane")


@case("T1-S02b", "admin API still answers with a token, 401 without one",
      "S-02 (control: the fix must not break the authorised path)")
def t_s02b(srv):
    check(srv.alive(), "server died")
    st, _, _ = parse(exchange(req("/_admin/health")))
    check(st == 401, f"expected 401 without Authorization, got {st}")
    got = exchange(req("/_admin/health", f"Authorization: Bearer {TOKEN}\r\n"))
    st2, _, body = parse(got)
    check(st2 == 200, f"expected 200 with a valid bearer token, got {st2}")


# --------------------------------------------------------------------------- #
# S-03 - request framing / smuggling
# --------------------------------------------------------------------------- #
@case("T1-S03a", "duplicate identical Content-Length is rejected (400)",
      "S-03 framing leniency -> smuggling, src/parser.c:192")
def t_s03a(srv):
    payload = (b"POST /ok.txt HTTP/1.1\r\nHost: localhost\r\n"
               b"Content-Length: 5\r\nContent-Length: 5\r\n\r\nhello")
    st, _, _ = parse(exchange(payload))
    check(st == 400, f"expected 400 for duplicate Content-Length, got {st}")


@case("T1-S03b", "conflicting Content-Length does not hang or get served",
      "S-03 (H1-033: the connection hung forever)")
def t_s03b(srv):
    payload = (b"POST /ok.txt HTTP/1.1\r\nHost: localhost\r\n"
               b"Content-Length: 5\r\nContent-Length: 6\r\n\r\nhello!")
    t0 = time.time()
    st, _, _ = parse(exchange(payload, idle=0.5, hard=3.0))
    dur = time.time() - t0
    check(st == 400, f"expected 400 for conflicting Content-Length, got {st} after {dur:.2f}s")


@case("T1-S03c", "comma-separated Content-Length (\"5, 5\") is rejected",
      "S-03 (H1-035: served as 200)")
def t_s03c(srv):
    payload = (b"POST /ok.txt HTTP/1.1\r\nHost: localhost\r\n"
               b"Content-Length: 5, 5\r\n\r\nhello")
    st, _, _ = parse(exchange(payload))
    check(st == 400, f"expected 400 for 'Content-Length: 5, 5', got {st}")


@case("T1-S03d", "Transfer-Encoding: xchunked is rejected, not treated as chunked",
      "S-03 (H1-038: served as 200)")
def t_s03d(srv):
    payload = (b"POST /ok.txt HTTP/1.1\r\nHost: localhost\r\n"
               b"Transfer-Encoding: xchunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
    st, _, _ = parse(exchange(payload))
    check(st == 400, f"expected 400 for 'Transfer-Encoding: xchunked', got {st}")


@case("T1-S03e", "Transfer-Encoding + Content-Length is rejected",
      "S-03: classic CL.TE / TE.CL smuggling primitive")
def t_s03e(srv):
    payload = (b"POST /ok.txt HTTP/1.1\r\nHost: localhost\r\n"
               b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"
               b"0\r\n\r\nGET /_admin/health HTTP/1.1\r\nHost: x\r\n\r\n")
    st, _, _ = parse(exchange(payload))
    check(st == 400, f"expected 400 when both CL and TE are present, got {st}")
    check(b"_admin" not in exchange(payload),
          "smuggled request appears to have been processed")


@case("T1-S03f", "Content-Length above the body limit is rejected with 413",
      "S-03 (H1-036: a 10-digit Content-Length was served as 200)")
def t_s03f(srv):
    payload = (b"POST /ok.txt HTTP/1.1\r\nHost: localhost\r\n"
               b"Content-Length: 99999999999\r\n\r\n")
    st, _, _ = parse(exchange(payload))
    check(st is not None, "no response to an oversized Content-Length")
    check(st in (400, 413), f"expected 400/413 for Content-Length: 99999999999, got {st}")


@case("T1-S03g", "malformed chunk framing is rejected with 400",
      "S-03 (H1-039/H1-041: no response at all)")
def t_s03g(srv):
    for bad in (b"POST /ok.txt HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"zz\r\nhello\r\n0\r\n\r\n",
                b"POST /ok.txt HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"ffffffffffffffffff\r\nhello\r\n0\r\n\r\n"):
        st, _, _ = parse(exchange(bad))
        check(st == 400, f"expected 400 for a malformed chunk size, got {st} "
                         f"(request={bad[:60]!r})")


# --------------------------------------------------------------------------- #
# S-04 - responses dropped on Connection: close / HTTP/1.0 / error paths
# --------------------------------------------------------------------------- #
@case("T1-S04a", "Connection: close still returns the response",
      "S-04 response discarded, src/conn.c:666")
def t_s04a(srv):
    got = exchange(req("/ok.txt", "Connection: close\r\n"))
    st, hdrs, body = parse(got)
    check(st == 200, f"expected 200 for 'Connection: close', got {st} "
                     f"({len(got)} bytes on the wire)")
    check(b"ok" in body, f"body missing: {body[:40]!r}")
    check(hdrs.get("connection", "").lower() == "close",
          f"expected 'Connection: close' in the response, got {hdrs.get('connection')!r}")


@case("T1-S04b", "HTTP/1.0 request is answered and the connection closes",
      "S-04 (H1-081: zero bytes returned)")
def t_s04b(srv):
    s = connect()
    try:
        s.sendall(b"GET /ok.txt HTTP/1.0\r\n\r\n")
        got = read_all(s)
        st, _, body = parse(got)
        check(st == 200, f"expected 200 for HTTP/1.0, got {st} ({len(got)} bytes)")
        closed, _ = closes_within(s, 2.0)
        check(closed, "HTTP/1.0 connection was not closed after the response")
    finally:
        s.close()


@case("T1-S04c", "a 400 raised by the parser is actually delivered",
      "S-04 (H1-083: zero bytes returned)")
def t_s04c(srv):
    got = exchange(b"GARBAGE\r\n\r\n")
    st, _, body = parse(got)
    check(st is not None, f"server sent {len(got)} bytes for a malformed request; "
                          f"the error response was dropped")
    check(st == 400, f"expected 400, got {st}")


@case("T1-S04d", "keep-alive connections stay usable after the fix",
      "S-04 (control: no regression in the normal path)")
def t_s04d(srv):
    s = connect()
    try:
        s.sendall(req("/ok.txt"))
        first = read_all(s, idle=0.3)
        st1, _, b1 = parse(first)
        check(st1 == 200, f"first response {st1}")
        s.sendall(req("/ok.txt"))
        second = read_all(s, idle=0.3)
        st2, _, b2 = parse(second)
        check(st2 == 200, f"second response on the same connection {st2}")
        check(b1 == b2, "body changed between requests on a keep-alive connection")
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# S-05 - no timeouts
# --------------------------------------------------------------------------- #
@case("T1-S05a", "a half-sent request header times out",
      "S-05 no header timeout, slowloris pins a worker slot forever", prof="short_timeouts")
def t_s05a(srv):
    check(srv.alive(), "server died")
    s = connect()
    try:
        s.sendall(b"GET /ok.txt HTTP/1.1\r\nHost: local")   # never terminated
        closed, dt = closes_within(s, 5.0)
        check(closed, f"connection still open after {dt:.1f}s with an incomplete "
                      f"request header (header timeout not enforced)")
        check(dt < 4.0, f"header timeout took {dt:.1f}s, expected ~2s")
    finally:
        s.close()


@case("T1-S05b", "an idle keep-alive connection is reclaimed",
      "S-05 idle connections never expire", prof="short_timeouts")
def t_s05b(srv):
    check(srv.alive(), "server died")
    s = connect()
    try:
        s.sendall(req("/ok.txt"))
        read_all(s, idle=0.3)
        closed, dt = closes_within(s, 5.0)
        check(closed, f"idle keep-alive connection still open after {dt:.1f}s "
                      f"(idle timeout not enforced)")
        check(dt < 4.0, f"idle timeout took {dt:.1f}s, expected ~2s")
    finally:
        s.close()


@case("T1-S05c", "a TCP connection that never starts the TLS handshake is dropped",
      "S-05 TLS handshake has no timeout", prof="short_timeouts")
def t_s05c(srv):
    check(srv.alive(), "server died")
    s = connect(srv.https)
    try:
        closed, dt = closes_within(s, 6.0)
        check(closed, f"TLS connection with no ClientHello still open after {dt:.1f}s")
        check(dt < 5.0, f"TLS handshake timeout took {dt:.1f}s, expected ~2-3s")
    finally:
        s.close()


@case("T1-S05d", "a slow-drip header attack is cut off",
      "S-05 slowloris: one byte per second keeps a connection alive indefinitely", prof="short_timeouts")
def t_s05d(srv):
    check(srv.alive(), "server died")
    s = connect()
    try:
        payload = req("/ok.txt")
        closed = False
        for i in range(len(payload)):
            try:
                s.sendall(payload[i:i + 1])
            except (BrokenPipeError, ConnectionResetError):
                closed = True
                break
            time.sleep(0.25)          # 0.25s/byte => the 2s header budget expires
            if i % 4 == 0:
                c, _ = closes_within(s, 0.05)
                if c:
                    closed = True
                    break
        if not closed:
            c, _ = closes_within(s, 3.0)
            closed = c
        check(closed, "a 1-byte-at-a-time header stream kept the connection open "
                      "for the whole request; slowloris is not mitigated")
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# S-06 - method confusion
# --------------------------------------------------------------------------- #
@case("T1-S06a", "DELETE is not served as GET",
      "S-06 methods fall through to the static handler, src/conn.c:390")
def t_s06a(srv):
    got = exchange(b"DELETE /ok.txt HTTP/1.1\r\nHost: localhost\r\n\r\n")
    st, hdrs, body = parse(got)
    check(st != 200, f"DELETE /ok.txt returned 200 and served a {len(body)}-byte body")
    check(st in (405, 501), f"expected 405/501 for DELETE, got {st}")
    if st == 405:
        check("allow" in hdrs, "405 response has no Allow header (RFC 9110 §15.5.6)")


@case("T1-S06b", "PUT is not served as GET",
      "S-06 (same root cause as S-06a)")
def t_s06b(srv):
    got = exchange(b"PUT /ok.txt HTTP/1.1\r\nHost: localhost\r\n"
                   b"Content-Length: 0\r\n\r\n")
    st, _, body = parse(got)
    check(st != 200, f"PUT /ok.txt returned 200 with body {body[:40]!r}")
    check(st in (405, 501), f"expected 405/501 for PUT, got {st}")


# --------------------------------------------------------------------------- #
# C-02 - byte-range syntax
# --------------------------------------------------------------------------- #
@case("T1-C02", "all four byte-range forms are interpreted per RFC 9110",
      "C-02 suffix and open-ended ranges, src/parser.c:158")
def t_c02(srv):
    expected = [
        ("bytes=0-3",            206, "bytes 0-3/5000",        4),
        ("bytes=-100",           206, "bytes 4900-4999/5000", 100),
        ("bytes=4990-",          206, "bytes 4990-4999/5000",  10),
        ("bytes=4990-4999",      206, "bytes 4990-4999/5000",  10),
        ("bytes=999999-1000000", 416, None, None),
        ("bytes=6000-",          416, None, None),
    ]
    for rng, want_st, want_cr, want_len in expected:
        st, hdrs, body = parse(exchange(req("/payload_5k.bin", f"Range: {rng}\r\n")))
        check(st == want_st, f"{rng}: status {st}, expected {want_st}")
        if want_cr:
            check(hdrs.get("content-range") == want_cr,
                  f"{rng}: Content-Range {hdrs.get('content-range')!r}, "
                  f"expected {want_cr!r}")
        if want_len is not None:
            check(len(body) == want_len,
                  f"{rng}: body is {len(body)} bytes, expected {want_len}")


# --------------------------------------------------------------------------- #
# C-01 - pipelining
# --------------------------------------------------------------------------- #
@case("T1-C01", "three pipelined requests get three responses",
      "C-01 pipelined bytes are only parsed when new data arrives, src/conn.c:266")
def t_c01(srv):
    s = connect()
    try:
        s.sendall(req("/ok.txt") * 3)
        got = read_all(s, idle=0.6, hard=3.0)
        n = got.count(b"HTTP/1.1 ")
        check(n == 3, f"sent 3 pipelined requests in one write, received {n} "
                      f"response(s) ({len(got)} bytes)")
        check(got.rstrip().endswith(b"ok"), "the third response body is missing")
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# runner
# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None, help="only run ids containing this substring")
    ap.add_argument("--out", default=os.path.join(ROOT, "tests", "regression",
                                                  "results", "track1.json"))
    args = ap.parse_args()

    if not os.access(BIN, os.X_OK):
        print(f"FATAL: {BIN} missing - run make first", file=sys.stderr)
        return 2

    try:                       # a stale log would hide the request we look for
        os.unlink(LOG)
    except OSError:
        pass

    results: list[Result] = []
    try:
        for cid, name, defect, prof, fn in REGISTRY:
            if args.only and args.only.lower() not in cid.lower():
                continue
            r = Result(id=cid, name=name, defect=defect)
            t0 = time.time()
            try:
                fn()
                r.status = "pass"
            except Fail as e:
                r.status = "fail"
                r.detail = str(e)
            except Exception as e:  # noqa: BLE001
                r.status = "fail"
                r.detail = f"{type(e).__name__}: {e}"
                r.trace = traceback.format_exc()
            print(f"[{r.status.upper():4}] {cid:9} {name[:58]:58} {time.time()-t0:5.2f}s"
                  f"{'  | ' + r.detail[:110] if r.detail else ''}")
            results.append(r)
    finally:
        shutdown_profiles()

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    passed = sum(1 for r in results if r.status == "pass")
    with open(args.out, "w") as f:
        json.dump({"results": [asdict(r) for r in results],
                   "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "binary_sha256": _sha256(BIN)}, f, indent=2)
    print(f"\n{passed}/{len(results)} passed  -> {args.out}")
    return 0 if passed == len(results) else 1


def _sha256(path: str) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


if __name__ == "__main__":
    sys.exit(main())
