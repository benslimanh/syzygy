# Local bug and security review

Date: 2026-11-13  
Baseline: `e55bf6751450adfc6e40805c9dd76ab77b84da0e`  
Fix branch: `fix/security-review`  
Repository: https://github.com/benslimanh/syzygy

## Summary

Built and ran the C server locally, reproduced defects with focused tests,
made local commits, and retested. No commits were pushed. This is a bounded
source review and local test campaign, **not a certification that the project
is free of vulnerabilities**.

## Confirmed findings and fixes

| Finding | Assessment | Evidence and remediation |
|---|---|---|
| HTTP/2 bypasses configured module policies | High; applies to TLS deployments relying on module-based authentication/WAF | An unauthenticated JWT-protected HTTP/1.1 request returned 401, while an HTTP/2 request returned 200. Module hooks are not wired into H2. TLS now advertises only HTTP/1.1 when any legacy or v1 module is configured. H2-only clients receive an ALPN negotiation failure. Tests check denial without a token and success with a valid token. |
| Intermediate symlinks escape the static document root | High; requires an intermediate symlink within the served tree pointing outside it | A local outside fixture was served with 200 over both H1 and H2 through `/escape/secret.txt`. Each URI component now opens relative to pinned directory descriptors with `O_NOFOLLOW`. Both protocols serve the validated descriptor, avoiding the old validation/reopen race. A unit test replaces the pathname after opening and verifies the descriptor still reads the original file. |
| Fragmented body handling retains stale buffer offsets/header views | High-risk memory-safety/framing defect; demonstrated broken fragmented requests, not arbitrary memory disclosure | CL and chunked authenticated requests split across read callbacks failed with broken pipes. Compaction retained an old `req_consumed` offset, allowing unsigned length underflow; header views also referenced the moved receive buffer. Offsets now reset after compaction, headers are retained in the request arena, and the chunk decoder reports consumed bytes before waiting for more input. Fragmented CL/chunked tests now pass, including an authenticated operation and synchronized follow-up GET. |
| Header limits/syntax can hide framing fields | Medium; parser disagreement/request-desynchronization risk | The parser silently skipped fields beyond 128 headers, accepted complete blocks above its 16 KiB cap, and accepted malformed names/values. Eight new parser assertions failed before the fix and pass afterwards. Excess fields/bytes and malformed syntax are rejected; valid tab OWS is accepted. |
| Vendored TLS dependency behind security maintenance | Dependency risk; applicability varies by feature and execution path | Upgraded mbedTLS 3.6.2 to 3.6.7 at `068ff080b369adfac81509f9b57b2afabaf82dc5`. Updated the submodule, lockfile, build documentation and Docker release/commit verification. The upstream `mbedtls/ChangeLog` documents security fixes including TLS error handling and memory-safety issues. No claim is made that every upstream advisory is exploitable in this server. |
| Parser fuzz target unusable/unsafe | Test tooling defect | `make fuzz` lacked the vendored include path; the harness included `parser.c` despite linking it separately and reset an uninitialized request (potential invalid free). Fixed includes, zero initialization, and cleanup. |
| Existing regression checks report false failures | Test tooling defects | Shell tests expected an obsolete 1,223-byte index file; now compare actual size and content. H2-020 failed to recognize EOF after initial SETTINGS; now records transport closure. H2-035 searched for `failed: 0`, but h2load prints `0 failed`; now validates return code and all seven request counters. No server-side bad-preface fix was needed. |

## Validation results

Final build uses mbedTLS 3.6.7. Local Linux x86-64 toolchain; tests use only
sandbox servers and generated fixtures.

| Check | Result |
|---|---|
| Main build | Pass |
| `make mod` | Pass; proxy-wasm remains its documented stub without WAMR |
| `make test` | 37 assertions pass |
| HTTP compatibility | 52/52 H1, 25/25 H2, 4/4 TLS pass |
| Existing Track 1 regressions | 24/24 pass |
| Existing shell security regressions | 43/43 checks pass |
| New path-confinement network regressions | 12/12 pass across H1/H2 |
| New JWT protocol-policy regressions | 4/4 pass |
| h2load fixed-count run | 2,000 succeeded, zero failed/errored/timeouts |
| Standalone parser fuzz target | 10,000 inputs, no sanitizer diagnostics |
| Full pipeline fuzzing | 3,444,932 inputs in 31 seconds, no crash artifacts/sanitizer findings |
| ASan/UBSan soak of final application | Requested 60 seconds; actual 82.5 seconds, 7,600 requests, 4 intentional worker kills, 3 reloads; no sanitizer diagnostics |
| ELF inspection | PIE, full RELRO/BIND_NOW, RW/non-executable GNU_STACK, stack protector; unsafe string symbols absent |

The soak recorded 56 client errors during its fault-injection workload;
this is not a zero-error throughput result. Vendored TLS archives were
release-built, not themselves sanitizer-instrumented. The Makefile's
fallback hardening display prints `NX?` because it uses non-wide readelf
output; independent `readelf -lW syzygy` confirms GNU_STACK is RW, not RWE.

## Re-run

```sh
git submodule update --init --recursive
make -C mbedtls -j4 CFLAGS='-O2 -fPIC' lib
make -j4
make mod
make certs
make test
# Install the h2 Python package in a virtualenv before the Python tests.
python3 tests/compat/run_all.py
python3 tests/regression/track1.py
python3 tests/regression/path_confinement.py
python3 tests/regression/module_protocol.py
bash tests/security_fixes.sh
make fuzz
./fuzz/parser_fuzz -runs=10000
make hardening-check
readelf -lW syzygy
```

The CI build job now runs the protocol suite and all three Python security
regression scripts in addition to unit tests. Workflow execution on GitHub
has not been performed.

## Remaining limitations / follow-up

- The README's historical sustained-duration HTTP/2 stall and high memory
  usage concerns are **not resolved by a successful 2,000-request test**.
  Longer load/resource-bounded testing and H2 allocation-lifetime review
  remain necessary.
- HTTP/2 does not support module hooks. The fix intentionally restricts
  module deployments to H1 rather than attempting a partial/unsafe hook port.
- The HTTP/2 admin route remains unsupported. Use HTTP/1.1.
- Static confinement does not make an attacker-writable document root safe
  against hard links, hostile mounts, or deliberately installed secrets.
  The configured root is trusted, and URI symlinks are disallowed.
- No exhaustive module/JWT/OPA/ModSecurity correctness audit or full
  transitive CVE/container/IaC scan was performed. WAMR integration, Docker
  image build, static/repro builds, Kubernetes, Helm, Terraform, and
  production deployment were not validated in this review.
- TLS test certificates are self-signed development material, not production
  certificates. The live preview is a demo with no authentication modules
  and no admin token; it must not be treated as a production deployment.

## Local commits

```text
3eaf13a reject oversized and ambiguous request headers
9417381 confine static files with pinned directory descriptors
9511508 fix parser fuzz build and request initialization
8299c67 fix false failures in tls and h2 regression checks
67bdd0f preserve body offsets and headers across fragmented reads
ff2c902 update mbedtls to 3.6.7 security release
54b5645 prevent h2 from bypassing configured module policies
```

An additional documentation/CI commit records this report and wires the
regressions into CI. Commit author is `Arena Agent`, not the repository
owner.

## Move the commits to your own clone

The exported `syzygy-fixes.bundle` contains the complete fix branch history
of the parent repository (not compiled binaries or submodule Git history).

```sh
# In your own clone, with the downloaded bundle path substituted:
git fetch /path/to/syzygy-fixes.bundle fix/security-review:fix/security-review
git switch fix/security-review
git submodule update --init --recursive
# Review, then publish only when ready:
git push -u origin fix/security-review
```

Prefer reviewing the branch through a pull request rather than pushing
straight to main. Fetch submodules from their configured upstreams before
building.
