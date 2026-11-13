# Changelog

## Unreleased

- Prevent HTTP/2 from bypassing authentication/WAF modules by restricting
  TLS ALPN to HTTP/1.1 whenever any module is configured.

- Reject oversized header blocks, excess headers, and malformed header syntax.
- Confine static-file lookups using directory-relative, no-symlink opens and
  retain validated descriptors through HTTP/1.1 and HTTP/2 file serving.
- Preserve request-body offsets and authentication headers across fragmented reads.
- Repair the parser fuzz target and false TLS/HTTP/2 regression failures.
- Update the vendored mbedTLS dependency from 3.6.2 to 3.6.7
  (`068ff080b369adfac81509f9b57b2afabaf82dc5`), including the lockfile and
  Docker build. Upstream fixes include TLS handshake error handling,
  cryptographic side channels, and malformed-input memory safety fixes.
  See `mbedtls/ChangeLog` for upstream details; applicability varies by
  enabled features and execution path.
