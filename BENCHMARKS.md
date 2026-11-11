# Benchmarks (2026-07-26)

These are loopback numbers from one Linux x86_64 machine running Debian 13
(trixie). syzygy ran with 4 worker processes (`-w 4`) on port 18080 with
`./www` as document root, built with the normal hardened flags from the
Makefile. Client and server share the machine, so the absolute figures say
more about that box than about syzygy.

For a comparison against nginx and HAProxy see
[bench/RESULTS.md](bench/RESULTS.md).

Tools:

- Apache Bench (`ab`) 2.3
- wrk 4.1.0
- Grafana k6 v0.57.0

Three setups were measured:

- no modules, only static files
- with JWT: `-M modules/jwt_auth.so`, HS256 verification plus the `iss` check
- with ModSecurity: `-M modules/modsec_real.so`, built against libmodsecurity
  3.0.14 with its built-in SQLi/XSS rules (ids 1001-1004). This is the real
  engine, not `modsec_stub.so`.

What was requested:

- `/ok.txt`, 3 bytes
- `/healthz`, 2 bytes, answered by the server itself
- `/payload_1k.bin`, 1.4 KiB of random data
- `/payload_16k.bin`, 21.6 KiB of random data
- `/_admin/*`, the JSON admin API
- `/metrics`, the Prometheus page

## 1. No modules

### 1.1 wrk, 15 s, 4 threads, 50 connections

| Endpoint          | Req/s  | Throughput | p50    | p90     | p99     |
|-------------------|--------|------------|--------|---------|---------|
| `/ok.txt` (3 B)   | 70 520 | 27.6 MB/s  | 655 µs | 2.38 ms | 13.1 ms |
| `/payload_1k.bin` | 70 051 | 120.0 MB/s | 674 µs | 1.00 ms | 2.93 ms |

### 1.2 ab, 50 000 requests, 100 connections

```
Complete requests:  50 000
Failed requests:    0
Requests/sec:        8 476
```

ab does not use keep-alive unless you ask for it, so this run opens a new
connection for every request. That is why it sits near 8.5k while wrk, which
reuses connections, reaches about 70k.

### 1.3 k6, 50 virtual users, 20 s, mixed requests (`k6/loadtest.js`)

```
✓ status 200 ........... 100.00%  280 951 / 280 951
✓ http_req_failed ...... 0.00%
  http_req_duration ... avg=3.49ms  p(95)=8.86ms  max=38.5ms
  http_reqs ........... 280 951  (14 046 req/s)
  data_received ....... 1.5 GB   (75 MB/s)
```

The script has two thresholds, `http_req_failed < 0.1%` and `p(95) < 50 ms`.
Both passed.

## 2. With JWT (HS256 and the iss claim)

The secret is the hex encoding of "secret". Every request carries a valid
`Authorization: Bearer <token>` header. Requests with a bad or missing token
were checked separately and get a 401.

wrk, 4 threads, 50 connections, 15 s, `/ok.txt`:

| Metric     | Value     |
|------------|-----------|
| Req/s      | 52 061    |
| Throughput | 20.4 MB/s |
| p50        | 860 µs    |
| p90        | 1.80 ms   |
| p99        | 11.5 ms   |

That is about 26% fewer requests per second than without the module.

## 3. With ModSecurity (libmodsecurity 3.0.14)

The module is built from `modules/modsec_real.cpp` and uses its built-in
rules.

wrk, 4 threads, 50 connections, 15 s, `/ok.txt`, clean requests only:

| Metric     | Value    |
|------------|----------|
| Req/s      | 21 278   |
| Throughput | 8.3 MB/s |
| p50        | 2.34 ms  |
| p90        | 3.36 ms  |
| p99        | 12.6 ms  |

Blocking was checked against the same running server:

```
GET /ok.txt?q=1' OR 1=1--   → 403  (SQLi rule)
GET /ok.txt                 → 200
```

The server did not crash during the run and none of the static files were
blocked by mistake.

## 4. Bugs fixed before this run

These came out of a security review and are fixed in the code that was
measured:

- `src/path.c` (high): a directory index is now opened with
  `openat(..., O_NOFOLLOW)` after the parent directory has been checked with
  `lstat()`, and then `fstat()`ed. A symlinked `index.html`, or a hard link
  pointing outside the root, is refused and no longer followed.
- `src/response.c` (high): `response_error()` and `dir_listing()` copy their
  body into the connection arena. Before, the response kept a pointer to a
  buffer on the stack.
- `src/h2.c` (high): the result of `arena_alloc()` is checked. Running out of
  memory gives an empty response where it used to be a NULL dereference.
- `src/admin.c` (high): the proxy endpoints under `/_admin/` check that the
  proxy is enabled before they take its mutex. Without `-P` they used to lock
  a mutex that was never initialised.
- `src/conn.c` (high): once HTTP/2 is negotiated over TLS the server keeps
  reading through `mbedtls_ssl_read()`. It used to hand raw ciphertext to
  nghttp2.
- `src/tls.c` (high): the ALPN list given to mbedTLS is a file-scope static
  array. It was a compound literal inside `tls_init()`, so mbedTLS was left
  with a dangling pointer. An unused ALPN callback is gone too.
- `src/modapi.c` (high): every `calloc()`, `malloc()` and `strdup()` in the
  shared dictionary, in `modapi_load()` and in `H_resp_set_header()` is
  checked.
- `src/server.c` (medium-high): reload and shutdown signal the worker PIDs
  the parent keeps in `children[]`, and workers put themselves in their own
  process group. The old `kill(0, ...)` hit everything in the group.
- `src/parser.c` and `src/conn.c` (medium-high): an unknown method is no
  longer turned into a GET. The parser marks it as unknown and the client
  gets a normal 501 response with a body.

## 5. Checking the binary

```
$ file syzygy
syzygy: ELF 64-bit LSB pie executable, x86-64, ..., dynamically linked, ...
$ readelf -d syzygy | grep FLAGS
   FLAGS   BIND_NOW
   FLAGS_1 NOW PIE
```

- PIE and full RELRO (`-Wl,-z,relro,-z,now`), so no lazy binding.
- `-fstack-protector-strong`, `-fstack-clash-protection` and
  `-fcf-protection=full`.
- `-D_FORTIFY_SOURCE=3`, `-fno-plt`, `-Wl,-z,noexecstack` and
  `-Wl,-z,separate-code`. `-rdynamic` is there for backtraces.
- `strcpy`, `sprintf` and `gets` do not show up in the dynamic symbol table.
  String handling goes through `memcpy` and `snprintf` with explicit lengths.
- Modules loaded with `-M` live in the same address space as the server and
  reach it through a table of function pointers. The older `-m` loader is
  still there for existing modules.
