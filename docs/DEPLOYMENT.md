# Deploying syzygy

These are notes for running syzygy on a Linux host with systemd (Debian 13,
Ubuntu 24.04, RHEL 9 and similar). The paths match `deploy/syzygy.service`.
Change them if you like, but then change them in the unit too.

## 1. Build and install

Build as described in the README, then copy things into place:

```sh
make -j"$(nproc)"

install -m 0755 syzygy /usr/local/sbin/syzygy
install -d -m 0755 /etc/syzygy /var/log/syzygy /var/lib/syzygy/www
install -m 0644 cert.pem /etc/syzygy/cert.pem
install -m 0600 key.pem  /etc/syzygy/key.pem
install -m 0644 deploy/syzygy.service   /etc/systemd/system/syzygy.service
install -m 0644 deploy/syzygy.logrotate /etc/logrotate.d/syzygy
```

`cert.pem` and `key.pem` are your real certificate and key. The pair from
`make certs` is self-signed and only good for trying things out.

`make install` exists too, but it puts the binary in `/usr/local/bin`. The
unit expects `/usr/local/sbin`, so either copy by hand as above or edit
`ExecStart`.

Create the user the service runs as:

```sh
useradd -r -s /usr/sbin/nologin -d /var/lib/syzygy syzygy
chown -R syzygy:syzygy /var/lib/syzygy /var/log/syzygy
```

The key file has to be readable by that user as well.

Before you start, it doesn't hurt to check that the binary was built with the
hardening flags:

```sh
make hardening-check
```

## 2. systemd

There are two unit files in the repo.

`deploy/syzygy.service` is the one to use. It runs as the `syzygy` user on
ports 8080 and 8443 and locks the process down:

- `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
  `PrivateDevices`, `MemoryDenyWriteExecute` and a few more. Only
  `/var/log/syzygy` and `/var/lib/syzygy` are writable.
- `CAP_NET_BIND_SERVICE` is the only capability left. Because of it you can
  change `-p 8080 -T 8443` to `-p 80 -T 443` in `ExecStart` and still not run
  as root.
- `Restart=always` with a one second delay. A crashed worker is restarted by
  syzygy's own parent process. systemd only steps in when the parent dies.
- `KillMode=mixed` with `TimeoutStopSec=10`: the parent gets SIGTERM, and
  whatever is still alive after ten seconds gets SIGKILL.
- `ExecReload` sends SIGHUP.
- Logs are written as JSON to `/var/log/syzygy/access.log` and also sent to
  syslog (`-l ... -S -j`).

The admin token comes from the `SYZYGY_ADMIN_TOKEN` environment variable. The
unit doesn't set it, so add a drop-in:

```sh
systemctl edit syzygy.service
```

```ini
[Service]
EnvironmentFile=/etc/syzygy/env
```

and put `SYZYGY_ADMIN_TOKEN=<something long and random>` into
`/etc/syzygy/env`, readable by root only. If the variable is empty the admin
API stays switched off.

Then:

```sh
systemctl daemon-reload
systemctl enable --now syzygy.service
systemctl status syzygy.service
journalctl -u syzygy.service -f
```

`systemd/syzygy.service` is a much simpler unit. It starts syzygy as root on
ports 80 and 443 and relies on the server dropping to `nobody` by itself. It
has none of the sandboxing above. `scripts/deploy.sh` installs that one for a
quick trial on a fresh machine.

## 3. Logs

`deploy/syzygy.logrotate` handles `/var/log/syzygy/*.log`. It keeps 14 old
files, compresses them, and sends SIGUSR1 after rotating so that the parent
and all workers reopen the log file.

```sh
logrotate -d /etc/logrotate.d/syzygy   # dry run, changes nothing
logrotate -f /etc/logrotate.d/syzygy   # force a rotation now
```

With `-S` the lines also go to syslog with the `LOG_DAEMON` facility, so
journald or syslogd pick them up without extra setup. If you want them in a
separate file with rsyslog:

```
:programname, isequal, "syzygy" /var/log/syzygy/syslog.log
& stop
```

## 4. Signals

| Signal | What happens |
|---|---|
| `SIGHUP` | The parent passes it to every worker. Each worker empties the response cache and reloads its modules. |
| `SIGUSR1` | Parent and workers reopen the `-l` log file. |
| `SIGTERM`, `SIGINT` | The parent stops the workers and exits. |

```sh
systemctl reload syzygy.service      # SIGHUP
systemctl kill -s SIGUSR1 syzygy     # reopen logs
```

A worker that dies unexpectedly is replaced by the parent, which logs a
warning when it happens.

## 5. TLS

- `-C` and `-K` take the certificate and the private key as PEM files.
- By default TLS 1.2 and 1.3 are both accepted. Add `-3` if you have no
  clients that still need 1.2.
- `-o <ciphers>` overrides the cipher list. Leave it alone unless you have a
  reason; the default is the mbedTLS one.
- ALPN offers `h2` and `http/1.1`. Clients that ask for `h2` get HTTP/2.

There is no OCSP stapling. If you need it, put a proxy that does it in front.

## 6. Modules

Modules are loaded with `-M path/to/module.so:config` and the flag can be
repeated. `make mod` builds them. For example:

```sh
./syzygy -p 8080 -T 8443 -C cert.pem -K key.pem -r ./www -w 4 \
    -M "modules/jwt_auth.so:secret_hex=736563726574,iss=syzygy" \
    -M modules/modsec_real.so:/etc/modsec/crs.conf
```

- `jwt_auth.so` verifies Bearer tokens (HS256/384/512, RS and ES algorithms).
- `modsec_real.so` is libmodsecurity. The part after the colon is the rules
  file. Without one it falls back to a few built-in rules.
- `proxy_wasm.so` loads proxy-wasm filters and has to be built with WAMR.

A module runs inside the worker process. If it crashes it takes that worker
with it, and the parent starts a new one.

## 7. Dropping privileges

If syzygy is started as root, it binds the listening sockets first and then,
before forking any worker, drops its supplementary groups and switches to the
group and user given with `-u` (default `nobody`). After that it checks that
it can no longer become root, and logs an error if it still can.

If it is not started as root none of this happens, which is the case with
`deploy/syzygy.service`. There systemd does the job through `User=` and the
capability settings.

## 8. Admin API

The endpoints under `/_admin/` need `Authorization: Bearer <token>`, where the
token is what you passed with `-A`. The comparison takes the same time
whatever the token looks like, including when the length is wrong. Without
`-A` the whole API answers 403.

| Method | Path | What it does |
|---|---|---|
| GET | `/_admin/health` | upstream health as JSON |
| GET | `/_admin/config` | running config as JSON |
| GET | `/_admin/dashboard` | small HTML status page |
| POST | `/_admin/up`, `/_admin/down` | mark an upstream up or down, body is `host:port` |
| POST | `/_admin/cache-purge` | empty the response cache |

The admin API only answers on HTTP/1.1. On an HTTP/2 connection these paths
return 404, so pass `--http1.1` when you use curl against the TLS port.

## 9. Smoke test after deploying

```sh
# is it up
curl -k https://127.0.0.1:8443/healthz

# byte range, expect 206
curl -k -s -o /dev/null -w "%{http_code}\n" -r 0-99 https://127.0.0.1:8443/index.html

# admin without a token, expect 401
curl -k --http1.1 -s -o /dev/null -w "%{http_code}\n" https://127.0.0.1:8443/_admin/config

# admin with the token, expect the config as JSON
curl -k --http1.1 -s -H "Authorization: Bearer <token>" https://127.0.0.1:8443/_admin/config

# made-up method, expect 501
curl -s -o /dev/null -w "%{http_code}\n" -X WHACKY http://127.0.0.1:8080/

# kill one worker, the server should keep answering
kill -9 "$(pgrep -P "$(systemctl show -p MainPID --value syzygy)" | head -1)"; sleep 1
curl -k https://127.0.0.1:8443/healthz
```

`tests/security_fixes.sh` runs a longer set of checks against a build in the
source tree and exits non-zero if one of them fails. It fits well as a CI
step after the build.

## 10. Running it directly on the internet

syzygy can listen on 80 and 443 itself, with nothing in front of it. That is
the same position nginx or HAProxy are usually in. What it has going for it:

1. TLS is terminated in the process by mbedTLS v3.6.2. `-3` limits it to TLS
   1.3.
2. It doesn't have to run as root. See sections 2 and 7.
3. Every worker is its own process with its own listening socket. A crash in
   one of them doesn't touch the others, and the parent replaces it.
4. All file access goes through `safe_resolve_path()`, which rejects `..` and
   opens files with `openat(O_NOFOLLOW)` followed by `fstat`. Symlinks that
   point out of the document root are not served.
5. Request data lives in a per-connection arena that is reset between
   requests.
6. Request bodies are capped at 1 MiB and answered with 413 above that. The
   chunked decoder checks the chunk sizes.
7. No `strcpy`, `sprintf` or `gets`, and the build flags listed in the
   README.
8. Slow clients are cut off by the header, idle and write timeouts.

Keep in mind that this is a 0.1 release and has not seen the years of abuse
that nginx or HAProxy have. The README lists the problems that are known
today. If you are not sure, put a CDN or a proxy in front of it.

A typical command line for the edge:

```sh
/usr/local/sbin/syzygy \
    -p 80 -T 443 \
    -C /etc/syzygy/cert.pem \
    -K /etc/syzygy/key.pem \
    -r /var/lib/syzygy/www \
    -w 0 \
    -3 \
    -A "$(openssl rand -hex 32)" \
    -l /var/log/syzygy/access.log \
    -S \
    -d
```

`-w 0` starts one worker per CPU. Note that the admin token generated here is
never shown to you, so store it somewhere first if you plan to use the admin
API.

## 11. Behind a CDN

If Cloudflare, CloudFront, Fastly or similar sits in front:

- Let the CDN terminate TLS for the visitors and fetch from syzygy over HTTPS.
- Give `-C` and `-K` the certificate the CDN expects from the origin.
- Don't let `/_admin/` through. Block the path at the CDN and reach the admin
  API from inside your network.

## 12. Performance

See `BENCHMARKS.md` and `bench/RESULTS.md` in the repository root. They were
measured on loopback, so run your own test on the hardware you deploy on
before you size anything.
