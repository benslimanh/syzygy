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
 * module.h - dlopen-based dynamic module system.
 * A module is a .so that exports syzygy_module_init (called once at load)
 * and syzygy_module_handle (called per request, may serve or filter).
 */
#ifndef SYZYGY_MODULE_H
#define SYZYGY_MODULE_H

#include "common.h"

struct conn;
struct http_response;

typedef struct syzygy_module {
    void *handle;
    char  name[64];
    int   (*on_request)(void *ctx, struct conn *c, struct http_response *r);
    void *ctx;
    struct syzygy_module *next;
} syzygy_module_t;

int   module_load(syzygy_module_t **list, const char *path);
int   module_invoke(syzygy_module_t *list, struct conn *c, struct http_response *r);
void  module_unload_all(syzygy_module_t *list);

#endif
