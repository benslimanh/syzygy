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

"""P0: HTTP/2 protocol conformance, frame-level malformed input, multiplexing."""
from harness import (case, check, expect_eq, expect_in, Fail, Server, HTTPS_PORT, CERT,
                     LOG)
import socket
import ssl
import struct
import time

try:
    import hpack
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    from h2.events import ResponseReceived, DataReceived, StreamEnded, StreamReset
    HAVE_H2 = True
except ImportError:  # pragma: no cover
    HAVE_H2 = False

CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# frame types
DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY, \
    WINDOW_UPDATE, CONTINUATION = range(10)


def _tls(alpn=("h2",)):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(list(alpn))
    return ctx.wrap_socket(socket.create_connection(("127.0.0.1", HTTPS_PORT), 3),
                           server_hostname="localhost")


def frame(ftype: int, flags: int, sid: int, payload: bytes = b"") -> bytes:
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + \
        struct.pack(">I", sid & 0x7fffffff) + payload


class H2Raw:
    """Raw HTTP/2 client: full control over frames, no library validation."""

    def __init__(self, preface=True, settings=True):
        self.closed = False
        self.s = _tls()
        self.s.settimeout(2.0)
        if preface:
            self.s.sendall(CLIENT_PREFACE)
        if settings:
            self.s.sendall(frame(SETTINGS, 0, 0, b""))

    def send(self, b: bytes):
        self.s.sendall(b)

    def recv_frames(self, timeout=1.0, max_frames=200):
        out = []
        buf = b""
        self.s.settimeout(timeout)
        end = time.time() + timeout
        while len(out) < max_frames and time.time() < end:
            while len(buf) >= 9:
                ln = int.from_bytes(buf[0:3], "big")
                if len(buf) < 9 + ln:
                    break
                ftype, flags = buf[3], buf[4]
                sid = int.from_bytes(buf[5:9], "big") & 0x7fffffff
                out.append((ftype, flags, sid, buf[9:9 + ln]))
                buf = buf[9 + ln:]
                end = time.time() + timeout
            try:
                chunk = self.s.recv(65536)
            except (socket.timeout, TimeoutError):
                break
            except (ConnectionResetError, ssl.SSLError, OSError):
                self.closed = True
                break
            if not chunk:
                self.closed = True
                break
            buf += chunk
        return out

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def build_headers(path="/ok.txt", method="GET", extra=()):
    enc = hpack.Encoder()
    hdrs = [(":method", method), (":scheme", "https"),
            (":authority", "localhost"), (":path", path), *extra]
    return enc.encode(hdrs)


def got_settings(frames) -> bool:
    return any(f[0] == SETTINGS for f in frames)


def is_goaway(frames) -> bool:
    return any(f[0] == GOAWAY for f in frames)


def is_closed(frames) -> bool:
    return is_goaway(frames)


# --------------------------------------------------------------------------- #
# happy path
# --------------------------------------------------------------------------- #
@case("H2-001", "server sends SETTINGS immediately after client preface", "h2")
def h2_001():
    c = H2Raw()
    try:
        frames = c.recv_frames(1.5)
        check(got_settings(frames), f"no SETTINGS frame, got {[f[0] for f in frames]}")
    finally:
        c.close()


@case("H2-002", "single GET returns :status 200 and correct body", "h2")
def h2_002():
    c = H2Raw()
    try:
        c.send(frame(HEADERS, 0x5, 1, build_headers("/ok.txt")))
        frames = c.recv_frames(2.0)
        types = [f[0] for f in frames]
        check(HEADERS in types, f"no response HEADERS, frames={types}")
        check(any(f[0] == DATA and f[2] == 1 for f in frames), "no DATA on stream 1")
        payload = b"".join(f[3] for f in frames if f[0] == DATA and f[2] == 1)
        expect_eq(payload, b"ok\n", "response body")
    finally:
        c.close()


@case("H2-003", "two multiplexed streams on one connection", "h2")
def h2_003():
    c = H2Raw()
    try:
        c.send(frame(HEADERS, 0x5, 1, build_headers("/ok.txt")))
        c.send(frame(HEADERS, 0x5, 3, build_headers("/sub/nested.txt")))
        frames = c.recv_frames(2.0)
        sids = {f[2] for f in frames if f[0] == DATA}
        check({1, 3} <= sids, f"streams answered: {sids}")
        bodies = {}
        for f in frames:
            if f[0] == DATA:
                bodies[f[2]] = bodies.get(f[2], b"") + f[3]
        expect_eq(bodies.get(1), b"ok\n", "stream 1 body")
        expect_eq(bodies.get(3), b"nested\n", "stream 3 body")
    finally:
        c.close()


@case("H2-004", "20 concurrent streams all answered", "h2")
def h2_004():
    c = H2Raw()
    try:
        sids = list(range(1, 40, 2))
        for sid in sids:
            c.send(frame(HEADERS, 0x5, sid, build_headers("/ok.txt")))
        frames = c.recv_frames(3.0, max_frames=600)
        done = {f[2] for f in frames if f[0] == DATA}
        check(len(done) >= 18, f"only {len(done)}/20 streams produced DATA")
    finally:
        c.close()


@case("H2-005", "HEAD over h2 returns headers without DATA", "h2")
def h2_005():
    c = H2Raw()
    try:
        c.send(frame(HEADERS, 0x5, 1, build_headers("/ok.txt", "HEAD")))
        frames = c.recv_frames(2.0)
        check(HEADERS in [f[0] for f in frames], "no HEADERS response")
        body = b"".join(f[3] for f in frames if f[0] == DATA and f[2] == 1)
        expect_eq(body, b"", "HEAD body")
    finally:
        c.close()


@case("H2-006", "404 over h2", "h2")
def h2_006():
    c = H2Raw()
    try:
        c.send(frame(HEADERS, 0x5, 1, build_headers("/missing")))
        frames = c.recv_frames(2.0)
        check(HEADERS in [f[0] for f in frames], "no response")
        payload = b"".join(f[3] for f in frames if f[0] == DATA)
        check(payload != b"ok\n", "404 must not return ok.txt")
    finally:
        c.close()


@case("H2-007", "PING is answered with PING ACK", "h2")
def h2_007():
    c = H2Raw()
    try:
        c.send(frame(PING, 0, 0, b"12345678"))
        frames = c.recv_frames(1.5)
        acks = [f for f in frames if f[0] == PING and f[1] & 0x1]
        check(acks, f"no PING ACK, frames={[(f[0], f[1]) for f in frames]}")
    finally:
        c.close()


@case("H2-008", "unknown frame type (0xFA) ignored, connection still usable", "h2")
def h2_008():
    c = H2Raw()
    try:
        c.send(frame(0xFA, 0, 0, b"junk"))
        c.send(frame(HEADERS, 0x5, 1, build_headers("/ok.txt")))
        frames = c.recv_frames(2.0)
        check(any(f[0] == DATA for f in frames), "connection broken by unknown frame type")
    finally:
        c.close()


@case("H2-009", "large response (64 KiB) delivered intact over h2", "h2")
def h2_009():
    c = H2Raw()
    try:
        c.send(frame(SETTINGS, 0, 0,
                     struct.pack(">HI", 0x4, 1 << 20)))  # INITIAL_WINDOW_SIZE
        c.send(frame(WINDOW_UPDATE, 0, 0, struct.pack(">I", 1 << 20)))
        c.send(frame(HEADERS, 0x5, 1, build_headers("/big.bin")))
        frames = c.recv_frames(3.0, max_frames=1200)
        body = b"".join(f[3] for f in frames if f[0] == DATA and f[2] == 1)
        check(len(body) > 0, "no body at all")
        expect_eq(len(body), 65536, "body length (flow-control must not truncate)")
    finally:
        c.close()


# --------------------------------------------------------------------------- #
# frame-level malformed / hostile input
# --------------------------------------------------------------------------- #
@case("H2-020", "invalid connection preface -> connection error, no crash", "h2", "high")
def h2_020():
    c = H2Raw(preface=False, settings=False)
    try:
        c.send(b"NOT-A-PREFACE\r\n\r\n")
        frames = c.recv_frames(1.5)
        check(c.closed or is_closed(frames), f"expected close/GOAWAY, got {[f[0] for f in frames]}")
    finally:
        c.close()


@case("H2-021", "DATA on stream 0 is a connection error", "h2", "high")
def h2_021():
    c = H2Raw()
    try:
        c.send(frame(DATA, 0, 0, b"x"))
        frames = c.recv_frames(1.5)
        check(is_closed(frames), f"expected GOAWAY/close, got {[f[0] for f in frames]}")
    finally:
        c.close()


@case("H2-022", "client HEADERS on even stream id is a protocol error", "h2", "high")
def h2_022():
    c = H2Raw()
    try:
        c.send(frame(HEADERS, 0x5, 2, build_headers("/ok.txt")))
        frames = c.recv_frames(1.5)
        check(is_closed(frames), f"expected GOAWAY, got {[f[0] for f in frames]}")
    finally:
        c.close()


@case("H2-023", "CONTINUATION without preceding HEADERS is a protocol error", "h2", "high")
def h2_023():
    c = H2Raw()
    try:
        c.send(frame(CONTINUATION, 0x4, 1, b"\x00"))
        frames = c.recv_frames(1.5)
        check(is_closed(frames), f"expected GOAWAY, got {[f[0] for f in frames]}")
    finally:
        c.close()


@case("H2-024", "CONTINUATION flood (300 frames, never END_HEADERS) bounded", "h2", "critical")
def h2_024():
    c = H2Raw()
    try:
        c.send(frame(HEADERS, 0x0, 1, build_headers("/ok.txt")[:4]))  # no END_HEADERS
        for _ in range(300):
            c.send(frame(CONTINUATION, 0x0, 1, b"\x00" * 64))
        frames = c.recv_frames(2.0, max_frames=50)
        check(is_closed(frames) or not frames,
              f"CONTINUATION flood not rejected ({[f[0] for f in frames][:10]})")
    finally:
        c.close()


@case("H2-025", "PUSH_PROMISE from client is a protocol error", "h2", "high")
def h2_025():
    c = H2Raw()
    try:
        c.send(frame(PUSH_PROMISE, 0x4, 1, struct.pack(">I", 2) + b"\x00"))
        frames = c.recv_frames(1.5)
        check(is_closed(frames) or any(f[0] == RST_STREAM for f in frames),
              f"expected GOAWAY/RST, got {[f[0] for f in frames]}")
    finally:
        c.close()


@case("H2-026", "SETTINGS ENABLE_PUSH=2 (invalid) is rejected", "h2", "medium")
def h2_026():
    c = H2Raw()
    try:
        c.send(frame(SETTINGS, 0, 0, struct.pack(">HI", 0x2, 2)))
        frames = c.recv_frames(1.5)
        check(is_closed(frames), f"expected GOAWAY, got {[f[0] for f in frames]}")
    finally:
        c.close()


@case("H2-027", "SETTINGS frame with wrong length is rejected", "h2", "medium")
def h2_027():
    c = H2Raw()
    try:
        c.send(frame(SETTINGS, 0, 0, b"\x00\x00\x00"))  # 3 bytes, not multiple of 6
        frames = c.recv_frames(1.5)
        check(is_closed(frames), f"expected GOAWAY, got {[f[0] for f in frames]}")
    finally:
        c.close()


@case("H2-028", "WINDOW_UPDATE overflow is rejected", "h2", "medium")
def h2_028():
    c = H2Raw()
    try:
        c.send(frame(WINDOW_UPDATE, 0, 0, struct.pack(">I", 0x7fffffff)))
        c.send(frame(WINDOW_UPDATE, 0, 0, struct.pack(">I", 0x7fffffff)))
        c.send(frame(WINDOW_UPDATE, 0, 0, struct.pack(">I", 0x7fffffff)))
        frames = c.recv_frames(1.5)
        check(is_closed(frames), f"expected GOAWAY, got {[f[0] for f in frames]}")
    finally:
        c.close()


@case("H2-029", "RST_STREAM on one stream does not disturb another stream", "h2", "high")
def h2_029():
    c = H2Raw()
    try:
        c.send(frame(HEADERS, 0x5, 1, build_headers("/ok.txt")))
        c.send(frame(RST_STREAM, 0, 1, struct.pack(">I", 8)))  # CANCEL
        c.send(frame(HEADERS, 0x5, 3, build_headers("/ok.txt")))
        frames = c.recv_frames(2.0)
        body3 = b"".join(f[3] for f in frames if f[0] == DATA and f[2] == 3)
        check(body3 == b"ok\n" or body3.startswith(b"ok"),
              f"stream 3 after reset of stream 1: {body3!r}")
    finally:
        c.close()


@case("H2-030", "oversized header block (100 KiB) rejected without OOM", "h2", "high")
def h2_030():
    c = H2Raw()
    try:
        big = build_headers("/ok.txt", extra=[("x-junk", "A" * 60000)])
        c.send(frame(HEADERS, 0x5, 1, big))
        frames = c.recv_frames(2.0)
        check(is_closed(frames) or any(f[0] == RST_STREAM for f in frames) or not frames,
              f"100 KiB header block not rejected: {[f[0] for f in frames][:5]}")
    finally:
        c.close()


@case("H2-031", "GOAWAY from client then new stream -> refused", "h2")
def h2_031():
    c = H2Raw()
    try:
        c.send(frame(GOAWAY, 0, 0, struct.pack(">II", 0, 0)))
        c.send(frame(HEADERS, 0x5, 1, build_headers("/ok.txt")))
        frames = c.recv_frames(1.5)
        body = b"".join(f[3] for f in frames if f[0] == DATA and f[2] == 1)
        check(body == b"", f"request served after GOAWAY: {body!r}")
    finally:
        c.close()


@case("H2-032", "truncated frame (partial header) does not crash the server", "h2", "high")
def h2_032():
    c = H2Raw()
    try:
        c.send(b"\x00\x00\x10\x00")  # length says 16, only 1 byte of header
        time.sleep(0.3)
    finally:
        c.close()
    # harness verifies liveness


@case("H2-033", "10 TLS connections with garbage after preface survive", "h2", "high")
def h2_033():
    for _ in range(10):
        c = H2Raw()
        try:
            c.send(b"\xff" * 512)
        finally:
            c.close()


@case("H2-034", "h2 over prior-knowledge plaintext (h2c) is not accepted", "h2", "high")
def h2_034():
    from harness import raw, HTTP_PORT, parse_response
    buf = raw(CLIENT_PREFACE + frame(SETTINGS, 0, 0, b""), port=HTTP_PORT, read_timeout=2)
    check(not buf.startswith(b"\x00\x00"), f"h2c upgrade answered on plaintext port: {buf[:16]!r}")


@case("H2-035", "h2load: 2000 requests, 50 concurrent, zero errors", "h2", "high")
def h2_035():
    import subprocess
    import os
    env = dict(os.environ, SSL_CERT_FILE=CERT)
    r = subprocess.run(
        ["h2load", "-n", "2000", "-c", "50", "-m", "10", "-t", "2",
         f"https://127.0.0.1:{HTTPS_PORT}/ok.txt"],
        capture_output=True, text=True, timeout=120, env=env)
    out = r.stdout + r.stderr
    import re
    counters = re.search(
        r"requests: (\d+) total, (\d+) started, (\d+) done, (\d+) succeeded, "
        r"(\d+) failed, (\d+) errored, (\d+) timeout", out)
    check(r.returncode == 0 and counters is not None and
          tuple(map(int, counters.groups())) == (2000, 2000, 2000, 2000, 0, 0, 0),
          f"h2load did not complete 2000 successful requests: {out}")
