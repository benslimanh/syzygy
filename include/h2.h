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
 * h2.h - HTTP/2 (nghttp2) integration.
 */
#ifndef SYZYGY_H2_H
#define SYZYGY_H2_H

#include "common.h"
#include <nghttp2/nghttp2.h>
#include "conn.h"

int  h2_session_init(conn_t *c);
void h2_session_destroy(conn_t *c);
int  h2_feed(conn_t *c, const uint8_t *data, size_t len);
int  h2_flush(conn_t *c);
int  h2_want_readwrite(conn_t *c, bool *want_read, bool *want_write);

#endif
