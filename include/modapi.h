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
 * modapi.h - Internal glue between core and the stable module ABI.
 *
 * Translates internal conn_t/http_request_t/http_response_t to the
 * stable syzygy_req_t / syzygy_resp_t opaque handles exposed in
 * syzygy_hooks.h. Core code never sees the module vtable directly.
 */
#ifndef SYZYGY_MODAPI_H
#define SYZYGY_MODAPI_H

#include "common.h"
#include "syzygy_hooks.h"

struct conn;

/* Runtime list of loaded modules */
typedef struct syzygy_modlist syzygy_modlist_t;

int   modapi_load(syzygy_modlist_t **ml, const char *path, const char *cfg,
                  size_t cfglen);
int   modapi_reload_all(syzygy_modlist_t *ml);
void  modapi_unload_all(syzygy_modlist_t *ml);

/* Invoke a phase across all modules until one HANDLED/DENY */
int   modapi_run_request_headers(syzygy_modlist_t *ml, struct conn *c);
int   modapi_run_response_headers(syzygy_modlist_t *ml, struct conn *c);

/* Shared dictionary (module_get/set/incr) */
int   modapi_shared_init(void);
void  modapi_shared_shutdown(void);
int64_t modapi_shared_incr(const char *scope, const char *k,
                           int64_t delta, int64_t initial, uint32_t ttl_sec);
int   modapi_shared_get(const char *scope, const char *k, char *out, size_t cap);
int   modapi_shared_set(const char *scope, const char *k, const char *v, uint32_t ttl_sec);

#endif
