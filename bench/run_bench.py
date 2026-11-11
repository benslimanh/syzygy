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
run_bench.py - reproducible three-way benchmark: syzygy vs nginx vs HAProxy.

Method
  * one machine, one kernel, loopback, no other load
  * CPU pinned: server processes on CPU 1, load generator on CPU 0
  * identical body ("ok\\n"), identical TLS material (self-signed RSA-2048,
    TLS 1.3 only), identical worker count (2), access logging off everywhere
  * warm-up ignored; N measured repetitions of fixed duration; median reported
  * per-request latency percentiles computed from h2load's raw timing log
  * server CPU time from /proc/<pid>/stat (whole process tree), peak RSS from
    VmHWM, error counts from h2load ("failed"/"errored"/"timeout")

Caveats (printed in the report as well)
  * syzygy serves the file from disk; HAProxy synthesises the response
  * 2 vCPU VM on shared cloud hardware: absolute numbers are lower than a
    dedicated box, ratios are what matter
  * HTTP/1.1 is measured with max 1 in-flight request per connection
    (keep-alive), because syzygy does not implement pipelining

Usage: python3 bench/run_bench.py [--reps 3] [--secs 8] [--out bench/RESULTS.md]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH = os.path.join(ROOT, "bench")
TMP = "/tmp/syzygy-bench"
FIXTURES = os.path.join(ROOT, "tests", "compat", "fixtures")
CERT = os.path.join(ROOT, "certs", "cert.pem")
KEY = os.path.join(ROOT, "certs", "key.pem")

NGINX = "/usr/sbin/nginx"
HAPROXY = "/usr/sbin/haproxy"
H2LOAD = shutil.which("h2load") or "/usr/bin/h2load"

SAL_TLS, SAL_PLAIN = 19443, 18081
NGX_TLS, NGX_PLAIN = 19444, 19081
HA_TLS, HA_PLAIN = 19445, 19082

CONNS_H1 = 50
CONNS_H2 = 25
STREAMS_H2 = 20


# --------------------------------------------------------------------------- #
def _raise_nofile():
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    want = 65536 if hard == resource.RLIM_INFINITY else min(65536, hard)
    resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))


def wait_port(port: int, timeout=10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.3).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def pids_of_tree(pid: int) -> list[int]:
    out = [pid]
    try:
        kids = subprocess.check_output(["pgrep", "-P", str(pid)], text=True).split()
    except subprocess.CalledProcessError:
        kids = []
    for k in kids:
        out += pids_of_tree(int(k))
    return out


class Proc:
    def __init__(self, name: str, cmd: list[str], ports: list[int], env=None,
                 pre=None):
        self.name = name
        self.cmd = cmd
        self.ports = ports
        self.env = env
        self.pre = pre
        self.p = None
        self.log = open(f"{TMP}/{name}.log", "ab", buffering=0)

    def start(self):
        if self.pre:
            self.pre()
        self.p = subprocess.Popen(["taskset", "-c", "1"] + self.cmd, cwd=ROOT,
                                  stdout=self.log, stderr=subprocess.STDOUT,
                                  env=self.env, start_new_session=True,
                                  preexec_fn=_raise_nofile)
        for port in self.ports:
            if not wait_port(port):
                raise RuntimeError(f"{self.name} did not listen on {port}")

    def tree(self):
        return pids_of_tree(self.p.pid) if self.p else []

    def cpu_seconds(self) -> float:
        total = 0.0
        for pid in self.tree():
            try:
                with open(f"/proc/{pid}/stat") as f:
                    parts = f.read().split()
                total += (int(parts[13]) + int(parts[14])) / os.sysconf("SC_CLK_TCK")
            except (OSError, IndexError):
                pass
        return total

    def hwm_mb(self) -> float:
        total = 0
        for pid in self.tree():
            try:
                with open(f"/proc/{pid}/status") as f:
                    for line in f:
                        if line.startswith("VmHWM:"):
                            total += int(line.split()[1])
            except OSError:
                pass
        return total / 1024.0

    def stop(self):
        if self.p and self.p.poll() is None:
            try:
                os.killpg(os.getpgid(self.p.pid), signal.SIGTERM)
                self.p.wait(10)
            except (subprocess.TimeoutExpired, ProcessLookupError):
                try:
                    os.killpg(os.getpgid(self.p.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        self.p = None


def syzygy_bin():
    return os.path.join(ROOT, "syzygy")


def servers() -> list[Proc]:
    env = dict(os.environ, SSL_CERT_FILE=CERT)

    def prep_ha():
        with open(f"{TMP}/haproxy.pem", "w") as out:
            for f in (CERT, KEY):
                out.write(open(f).read())

    return [
        Proc("syzygy",
             [syzygy_bin(), "-p", str(SAL_PLAIN), "-T", str(SAL_TLS),
              "-C", CERT, "-K", KEY, "-r", FIXTURES, "-w", "2", "-3",
              "-l", "/dev/null"],
             [SAL_PLAIN, SAL_TLS], env=env),
        Proc("nginx", [NGINX, "-c", f"{BENCH}/conf/nginx.conf"],
             [NGX_PLAIN, NGX_TLS], env=env),
        Proc("haproxy", [HAPROXY, "-f", f"{BENCH}/conf/haproxy.cfg",
                         "-db", "-q"],
             [HA_PLAIN, HA_TLS], env=env, pre=prep_ha),
    ]


# --------------------------------------------------------------------------- #
def percentiles(values: list[int]) -> dict:
    if not values:
        return {}
    v = sorted(values)

    def pct(p):
        k = max(0, min(len(v) - 1, int(round((p / 100.0) * (len(v) - 1)))))
        return v[k] / 1000.0  # us -> ms

    return {"p50": pct(50), "p95": pct(95), "p99": pct(99),
            "mean": statistics.fmean(v) / 1000.0}


def run_h2load(url: str, h1: bool, secs: int) -> dict:
    logfile = f"{TMP}/h2load.log"
    if os.path.exists(logfile):
        os.unlink(logfile)
    cmd = [H2LOAD, "-D", str(secs), "-c", str(CONNS_H1 if h1 else CONNS_H2),
           "-m", str(1 if h1 else STREAMS_H2), "-t", "1",
           "--log-file", logfile]
    if h1:
        cmd.append("--h1")
    cmd.append(url)
    env = dict(os.environ, SSL_CERT_FILE=CERT)
    r = subprocess.run(["taskset", "-c", "0"] + cmd, capture_output=True,
                       text=True, timeout=secs + 90, env=env,
                       preexec_fn=_raise_nofile)
    out = r.stdout + r.stderr
    stats = {"rps": 0.0, "ok": 0, "failed": 0, "errored": 0, "timeout": 0,
             "raw": out[-400:]}
    for line in out.splitlines():
        if line.startswith("finished in"):
            try:
                stats["rps"] = float(line.split(",")[1].strip().split()[0])
            except (IndexError, ValueError):
                pass
        if line.startswith("requests:"):
            parts = line.replace(",", " ").split()
            for i, tok in enumerate(parts):
                if tok in ("total", "succeeded,", "failed,", "errored,", "timeout"):
                    pass
            nums = {}
            for key in ("total", "succeeded", "failed", "errored", "timeout"):
                try:
                    idx = parts.index(key)
                    nums[key] = int(parts[idx - 1])
                except (ValueError, IndexError):
                    pass
            stats["ok"] = nums.get("succeeded", 0)
            stats["failed"] = nums.get("failed", 0)
            stats["errored"] = nums.get("errored", 0)
            stats["timeout"] = nums.get("timeout", 0)
    lat = []
    try:
        with open(logfile) as f:
            for line in f:
                p = line.rstrip("\n").split("\t")
                if len(p) >= 3 and p[1].startswith("2"):
                    lat.append(int(p[2]))
    except OSError:
        pass
    stats.update(percentiles(lat))
    stats["samples"] = len(lat)
    return stats


def cell(srv: Proc, plain_port: int, tls_port: int, mode: str, secs: int,
         reps: int) -> dict:
    """mode: h1-plain | h1-tls | h2-tls"""
    if mode == "h1-plain":
        url, h1 = f"http://127.0.0.1:{plain_port}/ok.txt", True
    elif mode == "h1-tls":
        url, h1 = f"https://127.0.0.1:{tls_port}/ok.txt", True
    else:
        url, h1 = f"https://127.0.0.1:{tls_port}/ok.txt", False

    run_h2load(url, h1, 2)  # warm-up, discarded
    runs = []
    for _ in range(reps):
        cpu0 = srv.cpu_seconds()
        st = run_h2load(url, h1, secs)
        cpu1 = srv.cpu_seconds()
        st["cpu_seconds"] = max(0.0, cpu1 - cpu0)   # workers may respawn mid-run
        st["cpu_us_per_req"] = (1e6 * st["cpu_seconds"] / st["ok"]) if st["ok"] else 0
        st["hwm_mb"] = srv.hwm_mb()
        runs.append(st)
    med = {
        "rps": statistics.median(r["rps"] for r in runs),
        "p50": statistics.median(r.get("p50", 0) for r in runs),
        "p95": statistics.median(r.get("p95", 0) for r in runs),
        "p99": statistics.median(r.get("p99", 0) for r in runs),
        "cpu_us_per_req": statistics.median(r["cpu_us_per_req"] for r in runs),
        "hwm_mb": max(r["hwm_mb"] for r in runs),
        "failed": sum(r["failed"] + r["errored"] + r["timeout"] for r in runs),
        "ok": sum(r["ok"] for r in runs),
        "runs": runs,
    }
    return med


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--secs", type=int, default=8)
    ap.add_argument("--out", default=os.path.join(BENCH, "RESULTS.md"))
    ap.add_argument("--json", default=os.path.join(BENCH, "results.json"))
    ap.add_argument("--servers", default="syzygy,nginx,haproxy")
    ap.add_argument("--modes", default="h1-plain,h1-tls,h2-tls")
    ap.add_argument("--merge", action="store_true",
                    help="merge results into an existing results.json")
    a = ap.parse_args()

    # pre-flight: kill leftovers from earlier runs, otherwise a stale master
    # keeps the ports and every measurement silently hits the wrong process
    for prog in ("nginx", "haproxy", "syzygy"):
        subprocess.run(["pkill", "-x", prog], capture_output=True)
    time.sleep(0.5)
    for port in (SAL_TLS, SAL_PLAIN, NGX_TLS, NGX_PLAIN, HA_TLS, HA_PLAIN):
        end = time.time() + 5
        while time.time() < end:
            try:
                socket.create_connection(("127.0.0.1", port), 0.2).close()
                time.sleep(0.2)
            except OSError:
                break
    os.makedirs(TMP, exist_ok=True)
    for f in os.listdir(TMP):
        try:
            os.unlink(os.path.join(TMP, f))
        except OSError:
            pass

    all_modes = [("h1-plain", "HTTP/1.1 cleartext, keep-alive"),
                 ("h1-tls", "HTTP/1.1 over TLS 1.3, keep-alive"),
                 ("h2-tls", "HTTP/2 over TLS 1.3, 20 streams/conn")]
    wanted_m = {m.strip() for m in a.modes.split(",")}
    wanted_s = {m.strip() for m in a.servers.split(",")}
    modes = [m for m in all_modes if m[0] in wanted_m]
    results: dict[str, dict] = {}
    if a.merge and os.path.exists(a.json):
        results = json.load(open(a.json))
    for srv in servers():
        if srv.name not in wanted_s:
            continue
        try:
            srv.start()
        except Exception as e:  # noqa: BLE001
            print(f"skip {srv.name}: {e}")
            srv.stop()
            continue
        ports = {srv.name: (SAL_PLAIN, SAL_TLS) if srv.name == "syzygy" else
                 ((NGX_PLAIN, NGX_TLS) if srv.name == "nginx" else (HA_PLAIN, HA_TLS))}[srv.name]
        for mode, label in modes:
            print(f"== {srv.name:8} {mode:9} ", end="", flush=True)
            try:
                res = cell(srv, ports[0], ports[1], mode, a.secs, a.reps)
                results.setdefault(mode, {})[srv.name] = res
                print(f"{res['rps']:9.0f} req/s  p50={res['p50']:.2f}ms "
                      f"p99={res['p99']:.2f}ms  cpu={res['cpu_us_per_req']:.0f}us/req "
                      f"rss={res['hwm_mb']:.0f}MiB err={res['failed']}")
            except subprocess.TimeoutExpired:
                print("STALLED (h2load hung: server stopped making progress)")
                results.setdefault(mode, {})[srv.name] = {"error": "stalled"}
            except Exception as e:  # noqa: BLE001
                print(f"FAILED {type(e).__name__}: {e}")
        srv.stop()
        time.sleep(0.4)

    with open(a.json, "w") as f:
        json.dump(results, f, indent=2)

    # ---------- markdown ----------
    host = subprocess.run(["bash", "-lc", "lscpu | sed -n 's/Model name: *//p' | head -1"],
                          capture_output=True, text=True).stdout.strip()
    lines = []
    lines.append("# syzygy vs nginx vs HAProxy — reproducible benchmark\n")
    lines.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}\n")
    lines.append(f"* Host: {host or 'n/a'}, {os.cpu_count()} vCPU, Debian 13 (trixie), loopback")
    lines.append(f"* Load generator: h2load {subprocess.run([H2LOAD, '--version'], capture_output=True, text=True).stdout.strip().split('/')[-1]}")
    lines.append(f"* CPU pinning: server tree on CPU 1, h2load on CPU 0")
    lines.append(f"* {a.reps} measured repetitions of {a.secs}s per cell; median reported; 2s warm-up discarded")
    lines.append(f"* Workers: 2 everywhere. TLS 1.3 only, same RSA-2048 self-signed cert.")
    lines.append(f"* Body: `ok\\n` (3 bytes). syzygy and nginx read it from disk; "
                 f"HAProxy synthesises it with `http-request return`.\n")
    lines.append("## Results\n")
    hdr = ("| Protocol | Server | Req/s | p50 (ms) | p95 (ms) | p99 (ms) | "
           "CPU µs/req | Peak RSS (MiB) | Errors |")
    sep = "|---|---|---|---|---|---|---|---|---|"
    for mode, label in modes:
        if mode not in results:
            continue
        lines.append(f"### {label}\n")
        lines.append(hdr)
        lines.append(sep)
        base = None
        for name in ("syzygy", "nginx", "haproxy"):
            r = results[mode].get(name)
            if not r:
                continue
            if name == "nginx":
                base = r["rps"]
            lines.append(
                f"| {mode} | {name} | {r['rps']:.0f} | {r['p50']:.2f} | {r['p95']:.2f} | "
                f"{r['p99']:.2f} | {r['cpu_us_per_req']:.0f} | {r['hwm_mb']:.0f} | {r['failed']} |")
        lines.append("")
        if base:
            sal = results[mode].get("syzygy", {}).get("rps", 0)
            lines.append(f"syzygy / nginx throughput ratio: **{sal/base:.2f}x**\n")

    lines.append("""## How to reproduce

```bash
make -j2                                  # syzygy (release build)
sudo apt-get install nginx haproxy nghttp2-client
python3 bench/run_bench.py --reps 3 --secs 8
```

Raw per-run data (all repetitions, not just medians) is in `bench/results.json`.

## Threats to validity

* **Shared cloud VM.** 2 vCPU with noisy neighbours; use the ratios, not the absolutes.
* **HAProxy is not a file server.** It returns a constant string while syzygy and
  nginx do an `open`/`fstat`/`read` cycle. That bias favours HAProxy.
* **HTTP/1.1 is keep-alive with 1 in-flight request per connection.** Pipelining is
  excluded because syzygy answers only the first request of a pipelined batch
  (defect H1-082 / H1-009 in `REPORT.md`).
* **No WAF/JWT numbers.** Those are module runs, out of scope for the reference set.
""")
    with open(a.out, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"\nwrote {a.out} and {a.json}")


if __name__ == "__main__":
    sys.exit(main())
