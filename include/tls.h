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
 * tls.h - mbedTLS initialisation and ALPN negotiation helpers.
 */
#ifndef SYZYGY_TLS_H
#define SYZYGY_TLS_H

#include "common.h"
#include "conn.h"

extern mbedtls_x509_crt       g_srvcert;
extern mbedtls_pk_context     g_srvkey;
extern mbedtls_ctr_drbg_context g_ctr_drbg;
extern mbedtls_entropy_context  g_entropy;
extern mbedtls_ssl_config    g_ssl_conf;

int  tls_init(const char *cert, const char *key, bool tls13_only,
              const char *ciphers, const char *ciphersuites);
int  tls_worker_init(void);
void tls_shutdown(void);
int  tls_handshake(conn_t *c);    /* SYZYGY_OK / AGAIN / ERR */

#endif
