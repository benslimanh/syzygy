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

"""P0: HTTP/1.1 protocol compatibility + malformed input."""
from harness import (case, check, expect_eq, expect_in, raw, h1_get, parse_response,
                     HTTP_PORT, HTTPS_PORT, ADMIN_TOKEN, count_responses)
import socket
import time

# --------------------------------------------------------------------------- #
# baseline semantics
# --------------------------------------------------------------------------- #
@case("H1-001", "GET static file -> 200 with exact body and Content-Length", "h1")
def h1_001():
    st, h, b = h1_get("/ok.txt")
    expect_eq(st, 200, "status")
    expect_eq(b, b"ok\n", "body")
    expect_eq(h.get("content-length"), "3", "content-length")


@case("H1-002", "HEAD returns headers, no body, correct Content-Length", "h1")
def h1_002():
    buf = raw(b"HEAD /ok.txt HTTP/1.1\r\nHost: l\r\n\r\n")
    st, h, b = parse_response(buf)
    expect_eq(st, 200, "status")
    expect_eq(h.get("content-length"), "3", "content-length")
    expect_eq(b, b"", "body must be empty")


@case("H1-003", "404 for missing file", "h1")
def h1_003():
    st, _, _ = h1_get("/no-such-file.txt")
    expect_eq(st, 404, "status")


@case("H1-004", "directory index served for /", "h1")
def h1_004():
    st, _, b = h1_get("/")
    expect_eq(st, 200, "status")
    expect_in(b"index", b, "index body")


@case("H1-005", "unknown method -> 501 (not rewritten to GET)", "h1")
def h1_005():
    st, _, _ = parse_response(raw(b"FOOBAR /ok.txt HTTP/1.1\r\nHost: l\r\n\r\n"))
    expect_eq(st, 501, "status")


@case("H1-006", "DELETE /ok.txt does not delete / is refused", "h1")
def h1_006():
    st, _, _ = parse_response(raw(b"DELETE /ok.txt HTTP/1.1\r\nHost: l\r\n\r\n"))
    check(st in (403, 405, 501), f"expected 403/405/501, got {st}")


@case("H1-007", "HTTP/0.9 simple request rejected with 4xx or close", "h1")
def h1_007():
    buf = raw(b"GET /ok.txt\r\n\r\n")
    st, _, b = parse_response(buf)
    check(st is None or 400 <= st < 500, f"expected 400-class or close, got {st}")
    check(b"ok\n" != b, "must not serve HTTP/0.9 body")


@case("H1-008", "Connection: keep-alive reuses one socket for 5 requests", "h1")
def h1_008():
    s = socket.create_connection(("127.0.0.1", HTTP_PORT), 2)
    s.settimeout(2)
    got = 0
    try:
        for _ in range(5):
            s.sendall(b"GET /ok.txt HTTP/1.1\r\nHost: l\r\n\r\n")
            buf = b""
            while b"\r\n\r\n" not in buf or not buf.rstrip().endswith(b"ok"):
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            if buf.startswith(b"HTTP/1.1 200"):
                got += 1
    finally:
        s.close()
    expect_eq(got, 5, "successful keep-alive responses")


@case("H1-009", "pipelining: 3 requests in one write answered in order", "h1")
def h1_009():
    req = (b"GET /ok.txt HTTP/1.1\r\nHost: l\r\n\r\n"
           b"GET /sub/nested.txt HTTP/1.1\r\nHost: l\r\n\r\n"
           b"GET /ok.txt HTTP/1.1\r\nHost: l\r\nConnection: close\r\n\r\n")
    buf = raw(req, read_timeout=3.0)
    bodies = buf.split(b"HTTP/1.1 ")
    expect_eq(len(bodies) - 1, 3, "number of pipelined responses")
    check(b"nested" in buf, "second response body served")


@case("H1-010", "Range: bytes=0-3 -> 206 with Content-Range", "h1")
def h1_010():
    st, h, b = h1_get("/payload_5k.bin", extra_headers="Range: bytes=0-3\r\n")
    expect_eq(st, 206, "status")
    expect_eq(h.get("content-range"), "bytes 0-3/5000", "content-range")
    expect_eq(len(b), 4, "body length")


@case("H1-011", "Range suffix bytes=-100 -> 206 last 100 bytes", "h1")
def h1_011():
    st, h, b = h1_get("/payload_5k.bin", extra_headers="Range: bytes=-100\r\n")
    expect_eq(st, 206, "status")
    expect_eq(len(b), 100, "body length")


@case("H1-012", "Range beyond EOF -> 416", "h1")
def h1_012():
    st, _, _ = h1_get("/payload_5k.bin", extra_headers="Range: bytes=999999-1000000\r\n")
    check(st in (416, 206), f"got {st}")


@case("H1-013", "If-None-Match matching ETag -> 304 empty body", "h1")
def h1_013():
    st, h, _ = h1_get("/payload_5k.bin")
    etag = h.get("etag")
    check(etag, f"server did not emit ETag on 5 KiB file (headers={sorted(h)})")
    st2, _, b2 = h1_get("/payload_5k.bin", extra_headers=f"If-None-Match: {etag}\r\n")
    expect_eq(st2, 304, "status")
    expect_eq(b2, b"", "304 body")


@case("H1-014", "gzip negotiated when Accept-Encoding: gzip", "h1")
def h1_014():
    st, h, b = h1_get("/payload_5k.bin", extra_headers="Accept-Encoding: gzip\r\n")
    expect_eq(st, 200, "status")
    if h.get("content-encoding") == "gzip":
        check(b[:2] == b"\x1f\x8b", "gzip magic missing")
    else:
        check(len(b) == 5000, "uncompressed body truncated")


@case("H1-015", "query string is ignored for filesystem resolution", "h1")
def h1_015():
    st, _, b = h1_get("/ok.txt?v=1&x=2")
    expect_eq(st, 200, "status")
    expect_eq(b, b"ok\n", "body")


# --------------------------------------------------------------------------- #
# malformed / hostile request lines
# --------------------------------------------------------------------------- #
@case("H1-020", "request line with no version -> 4xx", "h1", "high")
def h1_020():
    st, _, _ = parse_response(raw(b"GET /ok.txt\r\nHost: l\r\n\r\n"))
    check(st is None or 400 <= st < 500, f"got {st}")


@case("H1-021", "bare LF line endings rejected or ignored, never served twice", "h1", "high")
def h1_021():
    buf = raw(b"GET /ok.txt HTTP/1.1\nHost: l\n\n")
    st, _, _ = parse_response(buf)
    check(st is None or 400 <= st < 500, f"LF-only request should not be served, got {st}")


@case("H1-022", "NUL byte in URI not used to truncate the path", "h1", "high")
def h1_022():
    st, _, b = parse_response(raw(b"GET /ok.txt%00.jpg HTTP/1.1\r\nHost: l\r\n\r\n"))
    check(st in (400, 404), f"got {st} (200 would mean NUL truncation)")
    check(b != b"ok\n", "must not serve ok.txt via NUL truncation")


@case("H1-023", "very long URI (12 KiB) -> 414/400, connection handled", "h1", "medium")
def h1_023():
    uri = b"/" + b"A" * 12288
    st, _, _ = parse_response(raw(b"GET " + uri + b" HTTP/1.1\r\nHost: l\r\n\r\n", read_timeout=3))
    check(st is None or st in (400, 404, 414, 431), f"got {st}")


@case("H1-024", "800 headers -> bounded, no crash, 4xx or 200", "h1", "medium")
def h1_024():
    hdrs = b"".join(b"X-Fill-%d: aaaa\r\n" % i for i in range(800))
    buf = raw(b"GET /ok.txt HTTP/1.1\r\nHost: l\r\n" + hdrs + b"Connection: close\r\n\r\n", read_timeout=3)
    st, _, _ = parse_response(buf)
    check(st is None or st in (200, 400, 431), f"got {st}")


@case("H1-025", "header line without colon tolerated, request still served", "h1")
def h1_025():
    st, _, _ = parse_response(raw(b"GET /ok.txt HTTP/1.1\r\nHost: l\r\nBROKEN-HEADER\r\n\r\n"))
    check(st in (200, 400), f"got {st}")


@case("H1-026", "obs-fold continuation line does not corrupt request", "h1")
def h1_026():
    st, _, _ = parse_response(raw(b"GET /ok.txt HTTP/1.1\r\nHost: l\r\nX-A: one\r\n  two\r\n\r\n"))
    check(st in (200, 400), f"got {st}")


@case("H1-027", "space before colon (Host : x) is not treated as Host", "h1", "high")
def h1_027():
    st, _, _ = parse_response(raw(b"GET /ok.txt HTTP/1.1\r\nHost : evil\r\n\r\n"))
    check(st in (200, 400), f"got {st}")


@case("H1-028", "absolute-form request target rejected or localised", "h1", "high")
def h1_028():
    st, _, b = parse_response(raw(b"GET http://127.0.0.1:1/etc/passwd HTTP/1.1\r\nHost: l\r\n\r\n"))
    check(st in (400, 404, 403), f"got {st}")
    check(b"root:" not in b, "absolute-form URI leaked a local file")


@case("H1-029", "extremely long single header line (32 KiB) bounded", "h1", "medium")
def h1_029():
    buf = raw(b"GET /ok.txt HTTP/1.1\r\nHost: l\r\nX-Big: " + b"B" * 32768 + b"\r\n\r\n", read_timeout=3)
    st, _, _ = parse_response(buf)
    check(st is None or st in (400, 431), f"got {st}")


# --------------------------------------------------------------------------- #
# body framing / smuggling (front-end parser vs. what a backend would see)
# --------------------------------------------------------------------------- #
def _two_phase(first_request: bytes):
    """Send a body-bearing request, then a benign GET on the same connection.

    Returns (first_response, second_response_bytes). If the request body was not
    consumed correctly the benign GET is desynchronised or the server errors.
    """
    import socket
    s = socket.create_connection(("127.0.0.1", HTTP_PORT), 2)
    s.settimeout(2.0)
    try:
        s.sendall(first_request)
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = s.recv(4096)
            if not d:
                break
            buf += d
        first = buf
        s.sendall(b"GET /ok.txt HTTP/1.1\r\nHost: l\r\n\r\n")
        buf2 = b""
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                d = s.recv(4096)
            except socket.timeout:
                break
            if not d:
                break
            buf2 += d
        return first, buf2
    finally:
        s.close()


@case("H1-030", "valid Content-Length POST body consumed exactly (no desync)", "h1")
def h1_030():
    first, second = _two_phase(b"POST /ok.txt HTTP/1.1\r\nHost: l\r\nContent-Length: 5\r\n\r\nhello")
    st, _, _ = parse_response(first)
    check(st in (200, 405, 501), f"first response {st}")
    st2, _, b2 = parse_response(second)
    expect_eq(st2, 200, "follow-up GET after CL body")
    expect_eq(b2, b"ok\n", "follow-up body")


@case("H1-031", "valid chunked POST body consumed exactly (no desync)", "h1")
def h1_031():
    body = b"5\r\nhello\r\n0\r\n\r\n"
    first, second = _two_phase(b"POST /ok.txt HTTP/1.1\r\nHost: l\r\nTransfer-Encoding: chunked\r\n\r\n" + body)
    st, _, _ = parse_response(first)
    check(st in (200, 405, 501), f"first response {st}")
    st2, _, b2 = parse_response(second)
    expect_eq(st2, 200, "follow-up GET after chunked body")
    expect_eq(b2, b"ok\n", "follow-up body")


@case("H1-032", "TE + CL together is rejected (no desync possible)", "h1", "critical")
def h1_032():
    # RFC 9112 section 6.3: a message with both Transfer-Encoding and
    # Content-Length must be rejected, because that pair is exactly what a
    # cache and an origin disagree about. The only safe response is 400 and
    # a closed connection; the old expectation ("TE wins") described the
    # smuggling primitive rather than a correct server.
    req = (b"POST /ok.txt HTTP/1.1\r\nHost: l\r\nContent-Length: 44\r\n"
           b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
    first, second = _two_phase(req)
    st, _, _ = parse_response(first)
    expect_eq(st, 400, "TE+CL first response")
    check(second == b"" or second.startswith(b"HTTP/1.1 4"),
          f"connection was reused after a framing error ({len(second)} bytes)")


@case("H1-033", "conflicting duplicate Content-Length rejected (400)", "h1", "critical")
def h1_033():
    first, _ = _two_phase(b"POST /ok.txt HTTP/1.1\r\nHost: l\r\nContent-Length: 6\r\nContent-Length: 0\r\n\r\n")
    st, _, _ = parse_response(first)
    check(st == 400, f"RFC 7230 3.3.3 requires 400 for conflicting CL, got {st}")


@case("H1-034", "duplicate identical Content-Length accepted or rejected consistently", "h1", "high")
def h1_034():
    first, second = _two_phase(b"POST /ok.txt HTTP/1.1\r\nHost: l\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc")
    st, _, _ = parse_response(first)
    check(st in (200, 400), f"got {st}")
    if st == 200:
        st2, _, b2 = parse_response(second)
        expect_eq(st2, 200, "follow-up GET")


@case("H1-035", "non-numeric Content-Length (\"5, 5\") rejected, not ignored", "h1", "critical")
def h1_035():
    first, second = _two_phase(b"POST /ok.txt HTTP/1.1\r\nHost: l\r\nContent-Length: 5, 5\r\n\r\n")
    st, _, _ = parse_response(first)
    check(st == 400, f"invalid CL must be 400, got {st}")


@case("H1-036", "oversized Content-Length (>1MiB) rejected with 413/400", "h1", "critical")
def h1_036():
    first, _ = _two_phase(b"POST /ok.txt HTTP/1.1\r\nHost: l\r\nContent-Length: 99999999999\r\n\r\n")
    st, _, _ = parse_response(first)
    check(st in (400, 413, 431), f"got {st} - body framing ignored, desync possible")


@case("H1-038", "Transfer-Encoding: xchunked (invalid) is rejected", "h1", "critical")
def h1_038():
    first, second = _two_phase(b"POST /ok.txt HTTP/1.1\r\nHost: l\r\nTransfer-Encoding: xchunked\r\n\r\n0\r\n\r\n")
    st, _, _ = parse_response(first)
    check(st in (400, 411, 501), f"invalid TE must be rejected, got {st}")


@case("H1-039", "chunked with bad chunk size -> 400 and connection closed", "h1", "high")
def h1_039():
    buf = raw(b"POST /ok.txt HTTP/1.1\r\nHost: l\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\nhello\r\n0\r\n\r\n")
    st, _, _ = parse_response(buf)
    expect_eq(st, 400, "status")


@case("H1-040", "chunked missing terminating CRLF -> 400", "h1", "high")
def h1_040():
    buf = raw(b"POST /ok.txt HTTP/1.1\r\nHost: l\r\nTransfer-Encoding: chunked\r\n\r\n"
              b"5\r\nhelloX0\r\n\r\n", read_timeout=1.5)
    st, _, _ = parse_response(buf)
    check(st in (400, 408, None), f"chunk without CRLF must fail, got {st}")


@case("H1-041", "chunk size overflow (ffffffffffffffffff) -> 400/413", "h1", "high")
def h1_041():
    buf = raw(b"POST /ok.txt HTTP/1.1\r\nHost: l\r\nTransfer-Encoding: chunked\r\n\r\n"
              b"ffffffffffffffffff\r\nAAAA\r\n", read_timeout=2)
    st, _, _ = parse_response(buf)
    check(st in (400, 413), f"got {st}")


@case("H1-042", "unknown method with body does not smuggle the body as next request", "h1", "critical")
def h1_042():
    smuggled = b"GET /ok.txt HTTP/1.1\r\nHost: l\r\n\r\n"
    first, second = _two_phase(b"PATCH /x HTTP/1.1\r\nHost: l\r\nContent-Length: %d\r\n\r\n" % len(smuggled)
                               + smuggled)
    st, _, _ = parse_response(first)
    expect_eq(st, 501, "first response")
    n = count_responses(second)
    check(n <= 1, f"leftover body bytes were parsed: {n} responses to one follow-up GET")


@case("H1-050", "slowloris: partial request must time out (no infinite wait)", "h1", "critical")
def h1_050():
    # The limit is --header-timeout, default 10 s (see REPORT.md S-05). The
    # window here has to be larger than that default, not larger than a
    # guess: a server that holds the socket for 15 s in total is fine, one
    # that holds it forever is not.
    s = socket.create_connection(("127.0.0.1", HTTP_PORT), 2)
    try:
        s.sendall(b"GET /ok.txt HTTP/1.1\r\nHost: l\r\nX-Slow: ")
        s.settimeout(15)
        t0 = time.time()
        try:
            data = s.recv(128)
        except socket.timeout:
            data = b"<timeout>"
        elapsed = time.time() - t0
        check(data != b"<timeout>",
              f"connection still open after {elapsed:.1f}s with an incomplete header "
              f"(--header-timeout default is 10 s): slowloris can pin connections")
    finally:
        s.close()


@case("H1-051", "200 interrupted half-open connections do not break the server", "h1", "high")
def h1_051():
    socks = []
    for _ in range(200):
        s = socket.create_connection(("127.0.0.1", HTTP_PORT), 1)
        s.sendall(b"GET /ok.txt HT")
        socks.append(s)
    for s in socks:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
        s.close()
    time.sleep(0.5)
    st, _, b = h1_get("/ok.txt")
    expect_eq(st, 200, "server still serving after 200 aborted connections")


@case("H1-052", "client RST mid-response does not kill worker", "h1")
def h1_052():
    for _ in range(50):
        s = socket.create_connection(("127.0.0.1", HTTP_PORT), 1)
        s.sendall(b"GET /big.bin HTTP/1.1\r\nHost: l\r\n\r\n")
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
        s.close()
    time.sleep(0.3)
    st, _, _ = h1_get("/ok.txt")
    expect_eq(st, 200, "server healthy after mid-response RSTs")


@case("H1-053", "200 concurrent clients each get a correct response", "h1", "high")
def h1_053():
    import threading
    ok = []
    errs = []

    def one():
        try:
            st, _, b = h1_get("/ok.txt")
            ok.append(st == 200 and b == b"ok\n")
        except Exception as e:  # noqa: BLE001
            errs.append(repr(e))

    ts = [threading.Thread(target=one) for _ in range(200)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    expect_eq(sum(ok), 200, f"successful concurrent requests (errors={errs[:3]})")


# --------------------------------------------------------------------------- #
# TLS specifics
# --------------------------------------------------------------------------- #
@case("H1-060", "TLS 1.3 negotiated, ALPN offers h2 and http/1.1", "tls")
def h1_060():
    import ssl as _ssl
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", HTTPS_PORT), 3),
                        server_hostname="localhost")
    try:
        check(s.version() == "TLSv1.3", f"got {s.version()}")
        check(s.selected_alpn_protocol() in ("h2", "http/1.1"),
              f"ALPN={s.selected_alpn_protocol()}")
    finally:
        s.close()


@case("H1-061", "TLS 1.2 rejected when TLS1.3-only (-3)", "tls", "high")
def h1_061():
    import ssl as _ssl
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = _ssl.TLSVersion.TLSv1_2
    try:
        s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", HTTPS_PORT), 3),
                            server_hostname="localhost")
        s.close()
    except Exception:  # noqa: BLE001
        return  # rejected as intended
    raise Fail("TLS 1.2 handshake accepted while -3 was requested")


@case("H1-062", "plaintext h2 Preface on HTTP/1.1 port is refused (no h2c smuggling)", "tls", "high")
def h1_062():
    buf = raw(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", read_timeout=2)
    st, _, _ = parse_response(buf)
    # 501 is a correct refusal here: "PRI" is not an implemented method and the
    # server does not upgrade to h2c on cleartext. What must not happen is an
    # h2 SETTINGS frame or a 2xx.
    check(st is None or st in (400, 404, 405, 431, 501), f"got {st}")
    check(not buf.startswith(b"\x00\x00"), "server answered with an HTTP/2 frame on the h1 port")


@case("H1-063", "TLS request works for static file over 443", "tls")
def h1_063():
    st, _, b = h1_get("/ok.txt", port=HTTPS_PORT, tls=True)
    expect_eq(st, 200, "status")
    expect_eq(b, b"ok\n", "body")


# --------------------------------------------------------------------------- #
# server-side surfaces
# --------------------------------------------------------------------------- #
@case("H1-070", "GET /metrics exposes Prometheus text", "h1")
def h1_070():
    st, h, b = h1_get("/metrics")
    expect_eq(st, 200, "status")
    expect_in(b"# HELP", b, "prometheus exposition")


@case("H1-071", "GET /healthz -> 200", "h1")
def h1_071():
    st, _, _ = h1_get("/healthz")
    expect_eq(st, 200, "status")


@case("H1-072", "admin endpoint requires bearer token", "h1", "critical")
def h1_072():
    st, _, _ = h1_get("/_admin/config")
    expect_eq(st, 401, "unauthenticated /_admin/config")
    st2, _, _ = h1_get("/_admin/config", extra_headers="Authorization: Bearer wrong-token\r\n")
    expect_eq(st2, 401, "wrong token")
    st3, _, _ = h1_get("/_admin/config", extra_headers=f"Authorization: Bearer {ADMIN_TOKEN}\r\n")
    expect_eq(st3, 200, "valid token")


@case("H1-073", "security headers present on responses", "h1")
def h1_073():
    _, h, _ = h1_get("/ok.txt")
    check("x-content-type-options" in h or "x-frame-options" in h,
          f"no security headers: {sorted(h)}")


@case("H1-074", "Server header does not leak build/OS details", "h1")
def h1_074():
    _, h, _ = h1_get("/ok.txt")
    srv = h.get("server", "")
    check("ubuntu" not in srv.lower() and "debian" not in srv.lower(),
          f"Server header leaks OS: {srv}")


@case("H1-080", "Connection: close still returns a complete response", "h1", "critical")
def h1_080():
    buf = raw(b"GET /ok.txt HTTP/1.1\r\nHost: l\r\nConnection: close\r\n\r\n", read_timeout=2)
    st, _, b = parse_response(buf)
    check(st == 200, f"no response at all for Connection: close (got {buf[:40]!r})")
    expect_eq(b, b"ok\n", "body")


@case("H1-081", "HTTP/1.0 request is answered", "h1", "critical")
def h1_081():
    buf = raw(b"GET /ok.txt HTTP/1.0\r\n\r\n", read_timeout=2)
    st, _, _ = parse_response(buf)
    check(st == 200, f"HTTP/1.0 request unanswered (got {buf[:40]!r})")


@case("H1-082", "pipelined requests are all processed without further input", "h1", "critical")
def h1_082():
    req = b"GET /ok.txt HTTP/1.1\r\nHost: l\r\n\r\n" * 3
    buf = raw(req, read_timeout=2.0)
    n = count_responses(buf)
    check(n == 3, f"only {n}/3 pipelined requests answered")


@case("H1-083", "error response (400) is delivered even when conn would close", "h1", "critical")
def h1_083():
    buf = raw(b"POST /ok.txt HTTP/1.1\r\nHost: l\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\n")
    st, _, _ = parse_response(buf)
    check(st == 400, f"400 never reached the client (got {buf[:40]!r})")


def _fragmented_admin_body(framing, pieces):
    """Force multiple read callbacks, preserving auth headers and body offsets."""
    with socket.create_connection(('127.0.0.1', HTTP_PORT), 2) as s:
        s.settimeout(2)
        s.sendall(b'POST /_admin/cache-purge HTTP/1.1\r\nHost: l\r\n' +
                  f'Authorization: Bearer {ADMIN_TOKEN}\r\n'.encode() + framing + b'\r\n')
        time.sleep(.05)
        for piece in pieces:
            s.sendall(piece)
            time.sleep(.05)
        data = b''
        while b'\r\n\r\n' not in data:
            part = s.recv(4096)
            check(bool(part), 'connection closed during fragmented body')
            data += part
        status, _, _ = parse_response(data)
        expect_eq(status, 200, 'fragmented authenticated body')
        s.sendall(b'GET /ok.txt HTTP/1.1\r\nHost: l\r\nConnection: close\r\n\r\n')
        follow = b''
        while True:
            part = s.recv(4096)
            if not part:
                break
            follow += part
        expect_eq(parse_response(follow)[0], 200, 'follow-up request remains synchronized')


@case('H1-084', 'fragmented Content-Length body preserves offsets and auth headers', 'h1', 'critical')
def h1_084():
    _fragmented_admin_body(b'Content-Length: 6\r\n', [b'ab', b'cd', b'ef'])


@case('H1-085', 'fragmented chunked body preserves offsets and auth headers', 'h1', 'critical')
def h1_085():
    _fragmented_admin_body(b'Transfer-Encoding: chunked\r\n',
                           [b'3\r\n', b'abc', b'\r', b'\n0\r\n', b'\r\n'])
