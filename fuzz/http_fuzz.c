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
 * http_fuzz.c - full-surface libFuzzer harness for syzygy's request pipeline.
 *
 * The stock fuzz/parser_fuzz.c only calls http_request_parse(), which leaves
 * the chunked decoder and the path resolver completely unfuzzed. This harness
 * drives all three, selected by the first input byte:
 *
 *   0  parse only
 *   1  parse + chunked body decoder (when the request is chunked)
 *   2  safe_resolve_path only
 *   3  parse + chunked + path resolve (end-to-end, like a real request)
 *
 * Build:
 *   clang -O1 -g -fsanitize=fuzzer,address,undefined -Iinclude -D_GNU_SOURCE \
 *         -o fuzz/http_fuzz fuzz/http_fuzz.c src/parser.c src/path.c src/util.c -lz
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "parser.h"

#define ROOT "tests/compat/fixtures"

static void drive_chunked(http_request_t *req, const uint8_t *p, size_t n)
{
    size_t off = 0;
    bool done = false;
    int guard = 0;
    while (off < n && !done && guard++ < 512) {
        size_t consumed = 0;
        int rc = http_request_chunked_feed(req, (const char *)p + off, n - off,
                                           &consumed, &done);
        if (rc < 0) break;
        if (consumed == 0) {         /* no progress: feed one more byte */
            consumed = 1;
        }
        off += consumed;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2) return 0;
    unsigned mode = data[0] % 4;
    const uint8_t *body = data + 1;
    size_t blen = size - 1;

    static http_request_t req;
    http_request_reset(&req);

    if (mode == 2) {
        char out[SYZYGY_PATH_MAX];
        struct stat st;
        bool isdir = false;
        safe_resolve_path(ROOT, (const char *)body, blen, out, sizeof out, &st, &isdir);
        return 0;
    }

    size_t consumed = 0;
    int rc = http_request_parse(&req, (const char *)body, blen, &consumed);
    if (rc == 0 && (mode == 1 || mode == 3)) {
        if (req.body_kind == SYZYGY_BODY_CHUNKED && consumed <= blen)
            drive_chunked(&req, body + consumed, blen - consumed);
        if (mode == 3 && req.path && req.path_len) {
            char out[SYZYGY_PATH_MAX];
            struct stat st;
            bool isdir = false;
            safe_resolve_path(ROOT, req.path, req.path_len, out, sizeof out, &st, &isdir);
        }
    }
    http_request_reset(&req);
    return 0;
}
