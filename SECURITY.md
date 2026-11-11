# Security

## Reporting a bug

If you find a security problem, please don't open a public issue. Open a
private security advisory on this repository instead. You should get an
answer within 72 hours, and we can agree on when to disclose it.

## What syzygy does by default

- The HTTP parser has hard limits on the URI length, the number of headers
  and the body size. It is fuzzed with libFuzzer under ASan and UBSan; the
  harnesses are in `fuzz/` and `tests/fuzz/run_campaign.sh` runs them.
- `strcpy`, `strcat`, `sprintf` and `gets` are not linked into the binary.
  `make hardening-check` verifies that.
- Request paths with `..`, null bytes or backslashes are refused, and so are
  symlinks that lead out of the document root.
- TLS 1.2 is the minimum and `-3` restricts it to TLS 1.3. Responses over TLS
  carry an HSTS header with `preload`.
- When started as root, the server drops to an unprivileged user (`nobody`
  unless you pass `-u`) after binding its sockets.
- The container image runs as uid 65532. The compose file and the Kubernetes
  manifests add a read-only root filesystem and drop all capabilities, and
  on Kubernetes the `RuntimeDefault` seccomp profile is used.
- `make sbom` writes a basic SPDX file for the build.

## Supported versions

Only the 0.1.x line gets fixes.
