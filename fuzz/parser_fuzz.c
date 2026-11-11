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
 * parser_fuzz.c - libFuzzer harness for the HTTP/1.x parser.
 * Builds: make fuzz   (uses clang + -fsanitize=address,fuzzer,undefined)
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "../src/parser.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    http_request_t req;
    http_request_reset(&req);
    size_t consumed = 0;
    http_request_parse(&req, (const char*)data, size, &consumed);
    return 0;
}
