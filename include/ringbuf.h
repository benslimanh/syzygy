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
 * ringbuf.h - Single-producer single-consumer lock-free byte ring buffer,
 * used to decouple worker threads that produce JSON log lines from the
 * single logging thread that writes to stderr/file. On x86_64 the
 * acquire/release semantics are free via volatile stores; we use
 * __atomic builtins for portability.
 */
#ifndef SYZYGY_RINGBUF_H
#define SYZYGY_RINGBUF_H

#include "common.h"
#include <stdatomic.h>

typedef struct {
    uint8_t        *buf;
    size_t          cap;    /* power of two */
    atomic_size_t   head;   /* producer */
    atomic_size_t   tail;   /* consumer */
} ringbuf_t;

int  ringbuf_init(ringbuf_t *r, size_t cap);
void ringbuf_destroy(ringbuf_t *r);
size_t ringbuf_write(ringbuf_t *r, const void *src, size_t n);   /* returns bytes written */
size_t ringbuf_read(ringbuf_t *r, void *dst, size_t n);          /* returns bytes read */
bool   ringbuf_empty(ringbuf_t *r);

#endif
