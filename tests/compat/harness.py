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
harness.py - minimal dependency-light test harness for syzygy compatibility tests.

Provides:
  * Server      : lifecycle management (start/stop/restart/crash detection)
  * raw()       : raw TCP/TLS request/response exchange with timeouts
  * h1_get()    : convenience single-request helper
  * case()      : registry decorator
  * Expect      : assertion helpers that record structured evidence

No pytest required. Only `h2` (optional) for H2.
"""
from __future__ import annotations

import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import time
import traceback
from dataclasses import dataclass, field, asdict
from typing import Callable, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BIN = os.path.join(ROOT, "syzygy")
WWW = os.path.join(ROOT, "tests", "compat", "fixtures")
CERT = os.path.join(ROOT, "certs", "cert.pem")
KEY = os.path.join(ROOT, "certs", "key.pem")
LOG = "/tmp/syzygy-compat.log"

HTTP_PORT = 18080
HTTPS_PORT = 18443

ADMIN_TOKEN = "compat-admin-token-0123456789"


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #
@dataclass
class Result:
    id: str
    name: str
    proto: str
    status: str = "skip"          # pass | fail | error | skip
    detail: str = ""
    severity: str = "info"
    trace: str = ""


REGISTRY: list[tuple[str, str, str, str, Callable[[], None]]] = []


def case(cid: str, name: str, proto: str, severity: str = "info"):
    def deco(fn):
        REGISTRY.append((cid, name, proto, severity, fn))
        return fn
    return deco


class Fail(AssertionError):
    pass


class Blocked(Exception):
    """Raised when a precondition (e.g. protocol handshake) cannot be met."""
    pass


def check(cond, msg: str):
    if not cond:
        raise Fail(msg)


def expect_eq(got, want, label: str):
    if got != want:
        raise Fail(f"{label}: expected {want!r}, got {got!r}")


def expect_in(needle, hay, label: str):
    if needle not in hay:
        raise Fail(f"{label}: {needle!r} not found in {hay!r}")


# --------------------------------------------------------------------------- #
# server lifecycle
# --------------------------------------------------------------------------- #
class Server:
    def __init__(self, workers: int = 2, tls13_only: bool = True, extra: Optional[list[str]] = None):
        self.workers = workers
        self.tls13_only = tls13_only
        self.extra = extra or []
        self.proc: Optional[subprocess.Popen] = None

    def _wait_port(self, port: int, timeout: float = 8.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            try:
                s = socket.create_connection(("127.0.0.1", port), 0.25)
                s.close()
                return True
            except OSError:
                time.sleep(0.05)
        return False

    def start(self):
        args = [BIN, "-p", str(HTTP_PORT), "-T", str(HTTPS_PORT),
                "-C", CERT, "-K", KEY, "-r", WWW,
                "-w", str(self.workers), "-A", ADMIN_TOKEN, "-l", LOG]
        if self.tls13_only:
            args.append("-3")
        args += self.extra
        self.proc = subprocess.Popen(args, cwd=ROOT, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, start_new_session=True)
        if not self._wait_port(HTTP_PORT) or not self._wait_port(HTTPS_PORT):
            out = b""
            if self.proc.poll() is not None and self.proc.stdout:
                out = self.proc.stdout.read() or b""
            raise RuntimeError(f"server failed to start: {out.decode(errors='replace')[:2000]}")

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def workers_pids(self) -> list[int]:
        if not self.proc:
            return []
        try:
            out = subprocess.check_output(["pgrep", "-P", str(self.proc.pid)], text=True)
            return [int(x) for x in out.split()]
        except subprocess.CalledProcessError:
            return []

    def stop(self):
        for p in (self.proc,):
            if p and p.poll() is None:
                try:
                    os.killpg(os.getpgid(p.pid), signal.SIGTERM)
                except ProcessLookupError:
                    pass
        for p in (self.proc,):
            if p:
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
        self.proc = None

    def restart(self):
        self.stop()
        time.sleep(0.2)
        self.start()

    def log_tail(self, n: int = 40) -> str:
        try:
            with open(LOG, "r", errors="replace") as f:
                return "".join(f.readlines()[-n:])
        except OSError:
            return ""


# --------------------------------------------------------------------------- #
# raw HTTP
# --------------------------------------------------------------------------- #
def raw(data: bytes, port: int = HTTP_PORT, read_timeout: float = 2.0,
        tls: bool = False, max_wait: float = 0.35, alpn=None) -> bytes:
    """Send raw bytes, collect whatever the server returns within read_timeout."""
    s = None
    try:
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if alpn:
                ctx.set_alpn_protocols(alpn)
            s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), read_timeout),
                                server_hostname="localhost")
        else:
            s = socket.create_connection(("127.0.0.1", port), read_timeout)
        s.settimeout(read_timeout)
        if data:
            s.sendall(data)
        chunks = []
        deadline = time.time() + read_timeout
        idle_deadline = time.time() + max_wait
        while time.time() < deadline:
            if time.time() > idle_deadline:
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
            idle_deadline = time.time() + max_wait
        return b"".join(chunks)
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass


def parse_response(buf: bytes):
    """Return (status, headers dict, body) from the first response in buf."""
    if not buf:
        return None, {}, b""
    head, _, body = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    m = lines[0].split(b" ")
    if len(m) < 2 or not m[0].startswith(b"HTTP/"):
        return None, {}, body
    try:
        status = int(m[1])
    except ValueError:
        return None, {}, body
    hdrs = {}
    for ln in lines[1:]:
        if b":" in ln:
            k, _, v = ln.partition(b":")
            hdrs[k.strip().lower().decode(errors="replace")] = v.strip().decode(errors="replace")
    return status, hdrs, body


def h1_get(path: str, port: int = HTTP_PORT, tls: bool = False,
           extra_headers: str = "", read_timeout: float = 2.0):
    # NOTE: deliberately no "Connection: close" - syzygy drops responses for
    # such requests (see case H1-080); tests must isolate one variable each.
    req = (f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
           f"{extra_headers}\r\n").encode()
    return parse_response(raw(req, port=port, tls=tls, read_timeout=read_timeout))


def count_responses(buf: bytes) -> int:
    return buf.count(b"HTTP/1.")


# --------------------------------------------------------------------------- #
# runner
# --------------------------------------------------------------------------- #
def run(selected: Optional[set[str]] = None, out_json: str = "/tmp/compat-results.json"):
    results: list[Result] = []
    server = Server()
    try:
        server.start()
    except Exception as e:  # noqa: BLE001
        print(f"FATAL: cannot start server: {e}", file=sys.stderr)
        raise

    by_proto: dict[str, int] = {}
    try:
        for cid, name, proto, severity, fn in REGISTRY:
            if selected and cid not in selected:
                continue
            r = Result(id=cid, name=name, proto=proto, severity=severity)
            t0 = time.time()
            try:
                fn()
                r.status = "pass"
            except Blocked as e:
                r.status = "skip"
                r.detail = f"BLOCKED: {e}"
            except Fail as e:
                r.status = "fail"
                r.detail = str(e)
            except Exception as e:  # noqa: BLE001
                r.status = "error"
                r.detail = f"{type(e).__name__}: {e}"
                r.trace = traceback.format_exc()
            dur = time.time() - t0
            if not server.alive():
                r.status = "error"
                r.detail = (r.detail + " | SERVER PROCESS DIED").strip(" |")
            by_proto[proto] = by_proto.get(proto, 0) + 1
            print(f"[{r.status.upper():5}] {cid:8} {proto:5} {name[:62]:62} "
                  f"{dur*1000:6.0f}ms {'| ' + r.detail[:120] if r.detail else ''}")
            results.append(r)
            if not server.alive():  # restart for subsequent cases
                server.restart()
    finally:
        server.stop()

    summary = {}
    for r in results:
        summary.setdefault(r.proto, {"pass": 0, "fail": 0, "error": 0, "skip": 0})[r.status] += 1
    with open(out_json, "w") as f:
        json.dump({"results": [asdict(r) for r in results], "summary": summary,
                   "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, f, indent=2)

    print("\n=== summary ===")
    for proto, s in sorted(summary.items()):
        total = sum(s.values())
        print(f"{proto:6} {s['pass']:3}/{total:3} pass  fail={s['fail']} error={s['error']}")
    print(f"results -> {out_json}")
    return results
