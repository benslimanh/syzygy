# syzygy next to nginx and HAProxy

Measured on 2026-10-29 with `bench/run_bench.py`. The raw data of every run is
in `bench/results.json`.

## Setup

| Item | Value |
|---|---|
| Host | Intel Xeon @ 2.60 GHz, 2 vCPU, 1 GB RAM, Debian 13 (trixie) |
| Kernel / libc | glibc 2.41, loopback networking |
| Load generator | `h2load` (nghttp2 1.64.0) |
| CPU pinning | server process tree on CPU 1, `h2load` on CPU 0 (`taskset`) |
| Repetitions | 3 measured runs of 6 s per cell, median reported, 2 s warm-up thrown away |
| Concurrency | HTTP/1.1: 50 conns × 1 request in flight · HTTP/2: 25 conns × 20 streams |
| Workers | 2 everywhere (`worker_processes 2` / `nbthread 2` / `-w 2`) |
| TLS | TLS 1.3 only, same RSA-2048 self-signed certificate for all three |
| Logging | off everywhere (nginx `access_log off`, HAProxy no log target, syzygy `-l /dev/null`) |
| Body | `ok\n` (3 bytes) |
| Versions | syzygy 0.1.0 (`af9f0ea`, `-O2`, hardened), nginx 1.26.3, HAProxy 3.0.11 |

The latency percentiles are calculated from h2load's per-request log
(`--log-file`, one line per request) and not from its summary, so p50, p95 and
p99 cover every single request of a run.

HAProxy is marked with ¹ in the tables because it does not read a file here.
See the notes at the end.

## Results

### HTTP/1.1 cleartext, keep-alive

| Server | Req/s | p50 (ms) | p95 (ms) | p99 (ms) | CPU µs/req | Peak RSS | Errors |
|---|---|---|---|---|---|---|---|
| syzygy | 86 702 | 0.27 | 0.63 | 8.46 | 11 | 11 MiB | 0 |
| nginx | 100 448 | 0.28 | 0.65 | 8.40 | 10 | 28 MiB | 0 |
| HAProxy¹ | 155 095 | 0.29 | 0.40 | 1.30 | 6 | 36 MiB | 0 |

syzygy reaches 0.86× the throughput of nginx.

### HTTP/1.1 over TLS 1.3, keep-alive

| Server | Req/s | p50 (ms) | p95 (ms) | p99 (ms) | CPU µs/req | Peak RSS | Errors |
|---|---|---|---|---|---|---|---|
| syzygy | 67 900 | 0.34 | 4.40 | 8.53 | 15 | 14 MiB | 0 |
| nginx | 53 614 | 0.69 | 2.33 | 3.37 | 18 | 39 MiB | 0 |
| HAProxy¹ | 104 932 | 0.28 | 0.57 | 8.22 | 9 | 40 MiB | 0 |

syzygy reaches 1.27× the throughput of nginx here, with less CPU per request
and about a third of the memory. It is the best result of the three.

### HTTP/2 over TLS 1.3, 20 streams per connection

| Server | Req/s | p50 (ms) | p95 (ms) | p99 (ms) | CPU µs/req | Peak RSS | Errors |
|---|---|---|---|---|---|---|---|
| syzygy | stalled² | — | — | — | — | — | — |
| nginx | 123 277 | 4.05 | 4.80 | 6.27 | 8 | 39 MiB | 0 |
| HAProxy¹ | 142 818 | 1.82 | 10.36 | 13.11 | 7 | 67 MiB | 0 |

² syzygy could not be measured with a fixed duration. `h2load -D 5 -c 25 -m 20`
never comes back. The HTTP/2 connections that are open stop making progress,
while the server itself stays healthy: new HTTP/1.1 and new HTTP/2 connections
are answered normally. This happened on both attempts, see "HTTP/2 stall"
below. A run with a fixed number of requests, where h2load closes the
connections once it has them all, does work:

```
$ h2load -n 100000 -c 25 -m 20 -t 1 https://127.0.0.1:19443/ok.txt
finished in 1.77s, 56450 req/s
requests: 100000 total, 100000 started, 100000 done, 100000 succeeded, 0 failed
```

So on this machine syzygy tops out at about 56k req/s over HTTP/2 in short
bursts, which is roughly 0.45× nginx, and it cannot hold that for long.

## HTTP/2 stall, how to reproduce

```bash
./syzygy -p 18081 -T 19443 -C certs/cert.pem -K certs/key.pem -r tests/compat/fixtures -w 2 -3
SSL_CERT_FILE=certs/cert.pem h2load -D 5 -c 25 -m 20 -t 1 https://127.0.0.1:19443/ok.txt
#   -> no completion summary, h2load killed after 20 s
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18081/ok.txt        # 200, 1.5 ms
SSL_CERT_FILE=certs/cert.pem h2load -n 200 -c 2 -m 5 https://127.0.0.1:19443/ok.txt  # 200/200
```

The parent process is alive and the other connections keep working. The stuck
ones only recover when the client closes them. It doesn't look like a resource
limit, because 100k requests in a burst over the same number of connections go
through fine. The likely place is the HTTP/2 write path, either a connection
that is not picked up again after being idle or an epoll event that is not
re-armed.

## Memory under HTTP/2 load

The peak RSS of a worker is much higher than what it settles at:

| Scenario | Steady RSS | VmHWM (peak) |
|---|---|---|
| 2 workers idle | 3 MB each | 3 MB each |
| 1000 concurrent streams (50 conns × 20) | 6 MB each | 144 MB / 138 MB |

That is about 140 KB of peak heap for each concurrent HTTP/2 stream. At 10 000
concurrent streams it would add up to around 1.4 GB. On this 1 GB machine one
worker was killed by the OOM killer during the 50-connection run and started
again; the server log shows a second `worker 0 started`. This needs fixing
before the HTTP/2 numbers mean much.

## Things to keep in mind

* This is a shared cloud VM with 2 vCPUs, so other tenants add noise. Compare
  the servers with each other and don't read much into the absolute numbers.
  The ~70k req/s in `BENCHMARKS.md` comes from a different setup with 4
  workers and can't be compared with the 86k here, which needed both cores.
* HAProxy is not a file server. It answers `ok\n` from memory with
  `http-request return`, while syzygy and nginx go through
  `open`/`fstat`/`read`/`close`. That helps HAProxy in every table above.
* HTTP/1.1 was measured without pipelining (`-m 1`). At the measured commit
  syzygy answered only the first request of a pipelined batch (defect H1-082),
  so nginx and HAProxy were measured the same way to keep it fair.
* There are no rows for the WAF or JWT modules. `BENCHMARKS.md` has those.

## How to reproduce

```bash
make -j2                                                  # syzygy, normal build
sudo apt-get install -y nginx haproxy nghttp2-client
python3 bench/run_bench.py --reps 3 --secs 6               # writes RESULTS.md + results.json
```
