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
 * log.h - Structured JSON-capable async logging over a lock-free ring.
 */
#ifndef SYZYGY_LOG_H
#define SYZYGY_LOG_H

#include "common.h"
#include "ringbuf.h"

#define LOGF(lvl, fmt, ...) syzygy_log((lvl), (fmt), ##__VA_ARGS__)

void log_init_async(int fd, ringbuf_t *shared_ring);
void log_set_json(bool on);
void log_set_syslog(const char *ident, int facility);
void log_set_file(const char *path);   /* re-open; NULL = stderr */
void log_shutdown(void);

/* Worker side: enqueue a structured line (non-blocking).
 * If the ring is full the line is dropped (we count drops via metrics).
 */
void log_emit(int level, int worker_id, const char *remote,
              const char *method, const char *path, int status,
              size_t bytes, uint64_t duration_us);

void log_emit_plain(int level, const char *fmt, ...) SYZYGY_PRINTF(2,3);

#endif
void log_drain_to_backend(ringbuf_t *r);
