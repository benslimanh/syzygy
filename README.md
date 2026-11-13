# syzygy

syzygy is a small HTTP server written in C11. It speaks HTTP/1.1 and HTTP/2,
does its own TLS with mbedTLS, serves static files and can sit in front of
other servers as a reverse proxy. Everything ends up in one binary of about
1 MB.

This is version 0.1.0. There is a fair amount of testing behind it, but it is
a young project, so read [Known problems](#known-problems) before you depend
on it.

## Build

The instructions are for Debian 13 (trixie), which is also what `deps.lock`
is pinned against.

```bash
sudo apt-get install -y build-essential zlib1g-dev libnghttp2-dev libssl-dev
```

mbedTLS is a git submodule pinned to v3.6.7. Build it once, then build syzygy:

```bash
git submodule update --init --recursive
make -C mbedtls CFLAGS="-O2 -fPIC" lib
make -j4
```

Other targets you may want: `make test`, `make mod` (the plugin modules),
`make fuzz` (needs clang), `make static`, `make repro`, `make sbom`,
`make hardening-check` and `make install`.

## Run

```bash
make certs    # self-signed certificate for localhost, goes into certs/
./syzygy -p 8080 -T 8443 -C certs/cert.pem -K certs/key.pem -r ./www -w 0 -3
```

Then from another terminal:

```bash
curl http://localhost:8080/ok.txt
curl -k --http1.1 https://localhost:8443/ok.txt
curl -k --http2   https://localhost:8443/ok.txt
```

## What it does

- HTTP/1.1 with keep-alive and pipelining. Request bodies can be
  `Content-Length` or chunked and are capped at 1 MiB (you get a 413 above
  that). Methods it doesn't know get a 501.
- HTTP/2 over TLS, negotiated with ALPN. The framing is done by nghttp2.
- TLS 1.2 and 1.3 through mbedTLS. `-3` turns 1.2 off.
- Static files with ETag / 304, byte ranges (206) and gzip.
- A small in-memory response cache (LRU, entries expire).
- Reverse proxy with `-P host:port[:weight],...`: weighted round robin, a
  circuit breaker per upstream and active health checks. Least-connections
  and sticky (cookie or client IP) balancing exist in `src/proxy.c`, but
  nothing lets you select them yet.
- `/healthz` and Prometheus metrics on `/metrics`.
- Logs go to stderr, to a file (`-l`), to syslog (`-S`), as JSON if you pass
  `-j`.
- A handful of security headers on every response (nosniff, frame options,
  CSP, and HSTS when the connection is TLS).
- Header, idle and write timeouts.

Under the hood it is a pre-forked pool of worker processes. Each worker has
its own `SO_REUSEPORT` listener and its own epoll loop, and gives every
connection an arena that is reset between requests. If a worker dies the
parent starts a new one.

## Options

```
-p <port>          HTTP port (default 8080)
-T <port>          HTTPS port (default 8443, 0 turns it off)
-C <cert>          TLS certificate (PEM)
-K <key>           TLS private key (PEM)
-3                 TLS 1.3 only
-o <ciphers>       override the TLS cipher list
-r <dir>           document root (default ./www)
-u <user>          user to drop to when started as root (default nobody)
-w <n>             number of workers (0 = one per CPU)
-c                 disable TCP_CORK
-m <module.so>     load an old-style module (repeatable)
-M <mod.so[:cfg]>  load a v1 ABI module (repeatable)
-P <upstreams>     reverse proxy, comma separated upstreams
-l <path>          log file (SIGUSR1 reopens it)
-S                 also log to syslog
-Z                 disable gzip
-j                 JSON logs
-d                 daemonise
-A <token>         bearer token for /_admin/*
--header-timeout <ms>   time to send a full request header (default 10000)
--idle-timeout <ms>     keep-alive idle time (default 75000)
--write-timeout <ms>    time to accept a response (default 30000)
```

Signals:

- `SIGHUP` purges the cache and reloads the modules in every worker.
- `SIGUSR1` reopens the log file, which is what logrotate needs.
- `SIGTERM` and `SIGINT` shut the server down.

## Modules

Modules are shared objects loaded with `-M path.so:config`. They talk to the
server through a small versioned ABI (`include/syzygy_hooks.h`). `make mod`
builds the ones in `modules/`:

**Protocol policy:** when any `-m` or `-M` module is configured, TLS only
advertises HTTP/1.1. HTTP/2 does not yet run module hooks, so enabling it
would bypass authentication and WAF policies. H2-only clients are rejected.

- `jwt_auth` checks a Bearer JWT: HS256/384/512 with a shared secret, RS and
  ES algorithms with a public key, plus `exp`, `nbf` and `iss`. Config keys
  are `secret_hex=`, `pubkey_pem=`, `iss=` and `skip_path=`.
- `modsec_real` runs requests through libmodsecurity v3. Give it a rules file
  after the colon. It needs `libmodsecurity-dev` to build.
- `modsec_stub` is a small built-in rule set (rate limit per IP, SQLi/XSS
  signatures, scanner user agents) with no outside dependency.
- `extauthz_opa` asks an OPA server whether a request is allowed, without
  blocking the worker.
- `proxy_wasm` loads proxy-wasm filters through WAMR. Without `WASMRT` set at
  build time you only get a stub that refuses to load.
- `hello` is the sample for the old `-m` interface and answers on `/_hello`.

Example:

```bash
./syzygy -p 8080 -r ./www \
    -M "modules/jwt_auth.so:secret_hex=736563726574,iss=syzygy"
```

## Admin API

Start the server with `-A <token>` and send the token as
`Authorization: Bearer <token>`. Without `-A` every `/_admin/` request gets a
403.

| Method | Path | What it does |
|---|---|---|
| GET | `/_admin/config` | running config as JSON |
| GET | `/_admin/health` | upstream health as JSON |
| GET | `/_admin/dashboard` | small HTML status page |
| POST | `/_admin/up`, `/_admin/down` | mark an upstream up or down, body is `host:port` |
| POST | `/_admin/cache-purge` | empty the response cache |

## Hardening

The Makefile builds a PIE with full RELRO, stack protector, stack clash
protection, CET (`-fcf-protection=full`), `_FORTIFY_SOURCE=3` and a
non-executable stack. `make hardening-check` prints what the binary actually
has, and also checks that `strcpy`, `strcat`, `sprintf` and `gets` are not
linked in. The code doesn't use them.

When syzygy is started as root it binds its sockets and then drops to the
`-u` user before any worker is forked.

To report a security bug see [SECURITY.md](SECURITY.md).

## Tests

```bash
make test                          # parser unit tests
bash tests/security_fixes.sh       # regression script for past security bugs
python3 tests/compat/run_all.py    # HTTP/1.1, HTTP/2 and TLS cases
python3 tests/regression/track1.py
python3 tests/regression/path_confinement.py
python3 tests/regression/module_protocol.py # needs modules/jwt_auth.so
python3 tests/sanitizers/soak.py --duration 60 --workers 2
./tests/fuzz/run_campaign.sh       # libFuzzer + ASan/UBSan, needs clang
```

The scripts start the server themselves, so build it and run `make certs`
first. The compat suite also wants `pip install h2` and the `h2load` tool
(package `nghttp2-client`).

## Performance

Two sets of numbers are in the repo. Both are loopback runs on a single
machine, so take them as a rough idea and not more.

- [BENCHMARKS.md](BENCHMARKS.md): wrk against 4 workers. About 70k req/s for
  a small static file over plain HTTP/1.1, 52k with the JWT module loaded and
  21k with ModSecurity.
- [bench/RESULTS.md](bench/RESULTS.md): the same test against nginx and
  HAProxy on a 2 vCPU VM. Plain HTTP/1.1 comes out a bit slower than nginx
  (86.7k vs 100.4k req/s), HTTP/1.1 over TLS faster (67.9k vs 53.6k).

## Known problems

- HTTP/2 under sustained load. `bench/RESULTS.md` found that a fixed-duration
  `h2load` run stalls, and that a worker can peak at around 140 KB per
  concurrent stream. That report was taken at commit `af9f0ea`, so re-run it
  before trusting either the good or the bad numbers.
- `/_admin/` is not routed on HTTP/2 connections and returns 404 there. Use
  HTTP/1.1 for it (`curl --http1.1`).
- HTTP/2 module hooks are not implemented. With modules configured the
  server restricts ALPN to HTTP/1.1 to prevent policy bypass.
- The prior oversized-header defect (`H1-029`) is fixed. The bad-preface
  test (`H2-020`) now correctly recognizes a connection close after the
  initial server SETTINGS frame.

The local security review and validation scope are documented in
[docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md).

## Deployment

[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) walks through a systemd install. The
rest is in the tree:

```
deploy/, systemd/     systemd units and the logrotate config
Dockerfile            static build on a distroless image, with docker-compose.yml
k8s/, helm/           Kubernetes manifests and a Helm chart
terraform/            GKE cluster plus the Helm release
prometheus/, grafana/ alert rules, ServiceMonitor and a dashboard
k6/, bench/           load test script and the nginx/HAProxy comparison
```

## Source layout

```
src/        the server
include/    headers, including the module ABI
modules/    plugin modules
mbedtls/    mbedTLS submodule
tests/      unit, regression, compat, soak and fuzz scripts
fuzz/       libFuzzer harnesses and seed corpus
www/        sample document root
```

## License

MIT, see [LICENSE](LICENSE).
