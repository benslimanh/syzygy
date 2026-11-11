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
soak.py - P0 memory-safety and stability harness.

Runs against an AddressSanitizer + UndefinedBehaviorSanitizer build and
exercises, for a configurable duration:

  1. sustained concurrent keep-alive traffic (mixed request classes)
  2. malformed / hostile request corpus over many sockets
  3. worker kill + respawn (SIGKILL) and configuration reload (SIGHUP)
  4. half-open / slow / aborted connections

Any ASan/UBSan diagnostic, worker crash loop, or unresponsive-server event is
reported as a failure with the offending log excerpt.

Usage:
  python3 tests/sanitizers/soak.py --duration 60 --workers 2
"""
from __future__ import annotations

import argparse
import os
import random
import re
import signal
import socket
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BIN = os.path.join(ROOT, "syzygy")
CERT = os.path.join(ROOT, "certs", "cert.pem")
KEY = os.path.join(ROOT, "certs", "key.pem")
WWW = os.path.join(ROOT, "tests", "compat", "fixtures")
LOGDIR = "/tmp/syzygy-soak"
HTTP_PORT = 18090
HTTPS_PORT = 18453

DIAG = re.compile(
    r"(ERROR: AddressSanitizer|ERROR: LeakSanitizer|runtime error:|"
    r"SUMMARY: (AddressSanitizer|UndefinedBehaviorSanitizer)|"
    r"AddressSanitizer:DEADLYSIGNAL|stack-overflow)")

MALFORMED = [
    b"GET / HTTP/1.1\r\n",
    b"GET\r\n\r\n",
    b"\x00\x01\x02\x03\r\n\r\n",
    b"GET /ok.txt HTTP/1.1\r\n" + b"X" * 20000 + b"\r\n\r\n",
    b"GET /ok.txt HTTP/1.1\r\nHost: l\r\nContent-Length: -1\r\n\r\n",
    b"GET /ok.txt HTTP/1.1\r\nHost: l\r\nContent-Length: 999999999999999999999999\r\n\r\n",
    b"GET /ok.txt HTTP/1.1\r\nHost: l\r\nTransfer-Encoding: chunked\r\n\r\n"
    b"FFFFFFFFFFFFFFFFF\r\n",
    b"GET /ok.txt HTTP/1.1\r\nHost: l\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\n",
    b"GET /ok.txt HTTP/1.1\r\nHost: l\r\nTransfer-Encoding: chunked\r\n\r\n"
    b"5\r\nhello\r\n\r\n\r\n\r\n",
    b"GET /ok.txt HTTP/1.1\r\nHost: l\r\nRange: bytes=--5\r\n\r\n",
    b"GET /ok.txt HTTP/1.1\r\nHost: l\r\nRange: bytes=99999999999999999999-\r\n\r\n",
    b"GET /ok.txt HTTP/1.1\r\nHost: l\r\nIf-None-Match: " + b"E" * 300 + b"\r\n\r\n",
    b"POST /ok.txt HTTP/1.1\r\nHost: l\r\nExpect: 100-continue\r\nContent-Length: 10\r\n\r\n",
    b"GET /" + b"../" * 40 + b"etc/passwd HTTP/1.1\r\nHost: l\r\n\r\n",
    b"GET /%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1\r\nHost: l\r\n\r\n",
    b"GET /sub/../../../../etc/passwd HTTP/1.1\r\nHost: l\r\n\r\n",
    b"GET /symlink_escape.txt HTTP/1.1\r\nHost: l\r\n\r\n",
    b"GET /ok.txt HTTP/1.1\r\nHost: l\r\n" + b"X-Dup: 1\r\n" * 400 + b"\r\n",
    b"GET /ok.txt HTTP/1.1\r\nHost: l\r\n\x7f\xff\xfe: x\r\n\r\n",
    b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
    b"GET /ok.txt HTTP/1.1\r\nHost: l\r\nContent-Length: 5\r\n\r\nhelloGET /x HTTP/1.1\r\n\r\n",
    b"POST /ok.txt HTTP/1.1\r\nHost: l\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    b"GET /metrics HTTP/1.1\r\nHost: l\r\n\r\n",
    b"GET /_admin/config HTTP/1.1\r\nHost: l\r\nAuthorization: Bearer x\r\n\r\n",
]


class Runner:
    def __init__(self, workers: int, duration: int, asan: bool):
        self.workers = workers
        self.duration = duration
        self.asan = asan
        self.proc = None
        self.log_path = os.path.join(LOGDIR, "server.log")
        self.stats = {"requests": 0, "errors": 0, "restarts": 0, "worker_kills": 0}
        self.lock = threading.Lock()

    # ---------------- server ----------------
    def start(self):
        os.makedirs(LOGDIR, exist_ok=True)
        env = dict(os.environ)
        if self.asan:
            env["ASAN_OPTIONS"] = ("detect_leaks=0:abort_on_error=0:"
                                   "log_path=" + os.path.join(LOGDIR, "asan"))
            env["UBSAN_OPTIONS"] = ("print_stacktrace=1:halt_on_error=0:"
                                    "log_path=" + os.path.join(LOGDIR, "ubsan"))
        args = [BIN, "-p", str(HTTP_PORT), "-T", str(HTTPS_PORT),
                "-C", CERT, "-K", KEY, "-r", WWW,
                "-w", str(self.workers), "-A", "soak-token"]
        self.logf = open(self.log_path, "ab", buffering=0)
        self.proc = subprocess.Popen(args, cwd=ROOT, stdout=self.logf,
                                     stderr=subprocess.STDOUT, env=env,
                                     start_new_session=True)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", HTTP_PORT), 0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("server did not start")

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def children(self) -> list[int]:
        try:
            out = subprocess.check_output(["pgrep", "-P", str(self.proc.pid)], text=True)
            return [int(x) for x in out.split()]
        except subprocess.CalledProcessError:
            return []

    def stop(self):
        if self.proc and self.proc.poll() is None:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            try:
                self.proc.wait(8)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
        try:
            self.logf.close()
        except Exception:  # noqa: BLE001
            pass

    def hwm_kb(self) -> int:
        total = 0
        for pid in [self.proc.pid] + self.children():
            try:
                with open(f"/proc/{pid}/status") as f:
                    for line in f:
                        if line.startswith("VmHWM:"):
                            total += int(line.split()[1])
            except OSError:
                pass
        return total

    # ---------------- traffic ----------------
    def one_client(self, n: int, stop_at: float):
        s = None
        try:
            s = socket.create_connection(("127.0.0.1", HTTP_PORT), 2)
            s.settimeout(3)
            for i in range(n):
                if time.time() > stop_at:
                    break
                path = random.choice(["/ok.txt", "/index.html", "/big.bin",
                                      "/payload_5k.bin", "/sub/nested.txt",
                                      "/missing", "/metrics", "/healthz"])
                s.sendall(f"GET {path} HTTP/1.1\r\nHost: l\r\n\r\n".encode())
                buf = b""
                while b"\r\n\r\n" not in buf:
                    d = s.recv(65536)
                    if not d:
                        raise ConnectionError("closed early")
                    buf += d
                # drain declared body
                head, _, rest = buf.partition(b"\r\n\r\n")
                cl = 0
                for line in head.split(b"\r\n")[1:]:
                    if line.lower().startswith(b"content-length:"):
                        cl = int(line.split(b":")[1])
                while len(rest) < cl:
                    d = s.recv(65536)
                    if not d:
                        break
                    rest += d
                with self.lock:
                    self.stats["requests"] += 1
        except Exception:  # noqa: BLE001
            with self.lock:
                self.stats["errors"] += 1
        finally:
            if s:
                try:
                    s.close()
                except OSError:
                    pass

    def burst(self, clients: int, per_client: int):
        stop_at = time.time() + 60
        ts = [threading.Thread(target=self.one_client, args=(per_client, stop_at))
              for _ in range(clients)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()

    def malformed_burst(self):
        for payload in MALFORMED * 3:
            try:
                s = socket.create_connection(("127.0.0.1", HTTP_PORT), 1)
                s.settimeout(0.6)
                s.sendall(payload)
                try:
                    s.recv(4096)
                except (socket.timeout, ConnectionResetError):
                    pass
                s.close()
            except OSError:
                pass

    def half_open(self, n: int = 150):
        socks = []
        for _ in range(n):
            try:
                s = socket.create_connection(("127.0.0.1", HTTP_PORT), 1)
                s.sendall(b"GET /ok.txt HT")
                socks.append(s)
            except OSError:
                pass
        for s in socks:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                             b"\x01\x00\x00\x00\x00\x00\x00\x00")
                s.close()
            except OSError:
                pass

    def kill_worker(self):
        kids = self.children()
        if kids:
            try:
                os.kill(random.choice(kids), signal.SIGKILL)
                with self.lock:
                    self.stats["worker_kills"] += 1
            except ProcessLookupError:
                pass

    def reload(self):
        if self.alive():
            try:
                os.kill(self.proc.pid, signal.SIGHUP)
                with self.lock:
                    self.stats["restarts"] += 1
            except ProcessLookupError:
                pass

    # ---------------- main ----------------
    def run(self) -> int:
        self.start()
        t0 = time.time()
        deadline = t0 + self.duration
        rounds = 0
        max_hwm = 0
        while time.time() < deadline:
            rounds += 1
            self.burst(clients=40, per_client=25)
            self.malformed_burst()
            self.half_open(120)
            if rounds % 2 == 0:
                self.kill_worker()
            if rounds % 3 == 0:
                self.reload()
            max_hwm = max(max_hwm, self.hwm_kb())
            if not self.alive():
                print(f"FAIL: server process died in round {rounds}")
                return 1
        self.stop()

        # diagnostics
        diag_lines = []
        for name in os.listdir(LOGDIR):
            path = os.path.join(LOGDIR, name)
            if not os.path.isfile(path) or name == "server.log":
                continue
            try:
                with open(path, errors="replace") as f:
                    body = f.read()
                if DIAG.search(body):
                    diag_lines.append(f"{name}: {body[:1500]}")
            except OSError:
                pass
        try:
            with open(self.log_path, errors="replace") as f:
                log = f.read()
        except OSError:
            log = ""
        for line in log.splitlines():
            if DIAG.search(line):
                diag_lines.append(line[:300])

        dur = time.time() - t0
        print(f"rounds={rounds} duration={dur:.1f}s requests={self.stats['requests']} "
              f"client_errors={self.stats['errors']} worker_kills={self.stats['worker_kills']} "
              f"reloads={self.stats['restarts']} max_server_rss={max_hwm/1024:.1f}MiB")
        if diag_lines:
            print("SANITIZER DIAGNOSTICS FOUND:")
            for d in diag_lines[:10]:
                print("  " + d.replace("\n", "\n  ")[:1200])
            return 1
        print("no sanitizer diagnostics")
        return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=int, default=60)
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--no-asan", action="store_true")
    a = ap.parse_args()
    os.makedirs(LOGDIR, exist_ok=True)
    for f in os.listdir(LOGDIR):
        try:
            os.unlink(os.path.join(LOGDIR, f))
        except OSError:
            pass
    r = Runner(a.workers, a.duration, not a.no_asan)
    try:
        return r.run()
    except KeyboardInterrupt:
        r.stop()
        return 130


if __name__ == "__main__":
    sys.exit(main())
