/***************************************************************************
 *                                                                         *
 *   ____ ___  _ ____ ___  _ ________  _                                   *
 *  / ___\\  \///_   \\  \///  __/\  \//                                   *
 *  |    \ \  /  /   / \  / | |  _ \  /                                    *
 *  \___ | / /  /   /_ / /  | |_// / /                                     *
 *  \____//_/   \____//_/   \____\/_/                                      *
 *                                                                         *
 *  Syzygy                                                                 *
 *                                                                         *
 *  Created by Hamza Bensliman <benslimanh> for 2026                       *
 *                                                                         *
 *  This software is licensed under the terms of the MIT license.          *
 *  You may use, copy, modify, merge, publish, distribute and/or sell      *
 *  copies of the Software, and permit persons to whom the Software is     *
 *  furnished to do so, under the terms of the MIT license.                *
 *                                                                         *
 *  This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF  *
 *  ANY KIND, either express or implied.                                   *
 *                                                                         *
 ***************************************************************************/

/*
 * parser_test.c - Unit tests for the bounded HTTP parser and path helper.
 * Links against src/*.o built by the main Makefile.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "common.h"
#include "cache.h"
#include "proxy.h"
#include "parser.h"
#include "path.h"
#include "gzip_etag.h"

cache_t g_cache;
proxy_t g_proxy;

static int failures = 0;
http_request_t g_req;

#define EXPECT(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "  FAIL: %s\n", msg); failures++; } \
    else          { fprintf(stderr, "  ok:   %s\n", msg); } \
} while(0)

static void reset_req(void) { memset(&g_req, 0, sizeof g_req); }

static void test_simple_get(void)
{
    reset_req();
    const char msg[] =
        "GET /index.html HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: syzygy-test\r\n"
        "Accept-Encoding: gzip\r\n"
        "Connection: keep-alive\r\n"
        "If-None-Match: \"abc-def\"\r\n"
        "\r\n";
    size_t consumed = 0;
    int rc = http_request_parse(&g_req, msg, sizeof msg - 1, &consumed);
    EXPECT(rc == 0, "simple GET parses OK");
    EXPECT(g_req.method == HTTP_M_GET, "method GET");
    EXPECT(g_req.version == HTTP_VER_11, "version HTTP/1.1");
    EXPECT(g_req.path_len == 11 && memcmp(g_req.path, "/index.html", 11) == 0, "path /index.html");
    EXPECT(strcmp(g_req.host, "example.com") == 0, "host example.com");
    EXPECT(g_req.connection_close == false, "not connection:close");
    EXPECT(client_accepts_gzip(g_req.accept_encoding) == true, "accepts gzip");
    EXPECT(g_req.has_if_none_match, "has if-none-match");
}

static void test_traversal_blocked(void)
{
    char out[4096]; struct stat st; bool isd;
    /* If ./www doesn't exist yet, safe_resolve_path will fail; we only
     * need to confirm that ../ is rejected before stat happens. So we
     * point at / which is guaranteed to exist. */
    (void)mkdir("./www", 0755);
    int rc = safe_resolve_path("./www", "/../../../etc/passwd",
                               strlen("/../../../etc/passwd"),
                               out, sizeof out, &st, &isd);
    (void)rc;
    EXPECT(-1 == safe_resolve_path("./www", "/../etc/passwd",
            strlen("/../etc/passwd"), out, sizeof out, &st, &isd),
            "blocks ../ traversal");
}

static void test_chunked_headers(void)
{
    reset_req();
    const char p1[] = "GET /path HTTP/1.1\r\nHost: ex";
    const char p2[] = "ample.com\r\n\r\n";
    size_t consumed = 0;
    int rc = http_request_parse(&g_req, p1, sizeof p1 - 1, &consumed);
    EXPECT(rc == SYZYGY_RC_AGAIN, "partial headers return AGAIN");
    char buf[512]; size_t L = sizeof p1 - 1 + sizeof p2 - 1;
    memcpy(buf, p1, sizeof p1 - 1); memcpy(buf + sizeof p1 - 1, p2, sizeof p2 - 1);
    reset_req();
    rc = http_request_parse(&g_req, buf, L, &consumed);
    EXPECT(rc == 0, "full parse after concatenation");
    EXPECT(strcmp(g_req.host, "example.com") == 0, "host reassembled");
}

static void test_method_head(void)
{
    reset_req();
    const char m[] = "HEAD /a.txt HTTP/1.0\r\n\r\n";
    size_t c = 0;
    EXPECT(0 == http_request_parse(&g_req, m, sizeof m - 1, &c), "HEAD parses");
    EXPECT(g_req.method == HTTP_M_HEAD, "method HEAD");
    EXPECT(g_req.version == HTTP_VER_10, "version 1.0");
}

static void test_query(void)
{
    reset_req();
    const char m[] = "GET /foo?x=1&y=2 HTTP/1.1\r\nHost: a\r\n\r\n";
    size_t c = 0;
    EXPECT(0 == http_request_parse(&g_req, m, sizeof m - 1, &c), "query parse OK");
    EXPECT(g_req.query_len == 7 && memcmp(g_req.query, "x=1&y=2", 7) == 0, "query split");
    EXPECT(g_req.path_len == 4 && memcmp(g_req.path, "/foo", 4) == 0, "path split");
}

static void test_range(void)
{
    reset_req();
    const char m[] = "GET /f HTTP/1.1\r\nHost: a\r\nRange: bytes=100-199\r\n\r\n";
    size_t c = 0;
    int rc = http_request_parse(&g_req, m, sizeof m - 1, &c);
    EXPECT(rc == 0, "range parses");
    EXPECT(g_req.has_range, "has_range set");
    EXPECT(g_req.range_start == 100, "range_start=100");
}

static void test_header_limits(void)
{
    size_t c = 0;
    char msg[SYZYGY_MAX_HEADER_SZ + 128];
    size_t n = (size_t)snprintf(msg, sizeof msg, "POST / HTTP/1.1\r\n");
    for (int i = 0; i < SYZYGY_MAX_HEADERS; i++)
        n += (size_t)snprintf(msg + n, sizeof msg - n, "X: a\r\n");
    n += (size_t)snprintf(msg + n, sizeof msg - n,
                          "Content-Length: 5\r\n\r\nhello");
    reset_req();
    EXPECT(http_request_parse(&g_req, msg, n, &c) < 0,
           "reject framing header hidden beyond header count limit");

    n = (size_t)snprintf(msg, sizeof msg, "GET / HTTP/1.1\r\nX: ");
    memset(msg + n, 'a', SYZYGY_MAX_HEADER_SZ);
    n += SYZYGY_MAX_HEADER_SZ;
    memcpy(msg + n, "\r\n\r\n", 4); n += 4;
    reset_req();
    EXPECT(http_request_parse(&g_req, msg, n, &c) < 0,
           "reject complete oversized header block");

    const char *bad[] = {
        "POST / HTTP/1.1\r\nContent-Length : 5\r\n\r\n",
        "POST / HTTP/1.1\r\n Content-Length: 5\r\n\r\n",
        "GET / HTTP/1.1\r\nmissing-colon\r\n\r\n",
        "GET / HTTP/1.1\r\nX: a\nb\r\n\r\n",
        "GET / HTTP/1.1\r\n: empty\r\n\r\n",
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        reset_req();
        EXPECT(http_request_parse(&g_req, bad[i], strlen(bad[i]), &c) < 0,
               "reject malformed header syntax");
    }
    reset_req();
    const char valid[] = "POST / HTTP/1.1\r\nContent-Length:\t0\t\r\n\r\n";
    EXPECT(http_request_parse(&g_req, valid, sizeof valid - 1, &c) == 0 &&
           !g_req.framing_error && g_req.has_content_length,
           "accept tab OWS around header value");
}

int main(void)
{
    fprintf(stderr, "== parser_test ==\n");
    test_simple_get();
    test_traversal_blocked();
    test_chunked_headers();
    test_method_head();
    test_query();
    test_range();
    test_header_limits();
    fprintf(stderr, "\n%s: %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
