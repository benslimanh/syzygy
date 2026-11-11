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
 * metrics.c - Prometheus metrics in mmap'd shared memory (so each prefork
 * worker updates the same counters atomically).
 */
#include "metrics.h"
#include "cache.h"
#include "proxy.h"
#include <sys/mman.h>

metrics_t *g_metrics;
extern cache_t g_cache;

int metrics_init(void)
{
    g_metrics = mmap(NULL, sizeof(metrics_t),
                     PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (g_metrics == MAP_FAILED) { g_metrics = NULL; return -1; }
    memset(g_metrics, 0, sizeof *g_metrics);
    g_metrics->start_time = time(NULL);
    return 0;
}

void metrics_shutdown(void)
{
    if (g_metrics) { munmap(g_metrics, sizeof(metrics_t)); g_metrics = NULL; }
}

void metrics_incr_request(int status, size_t bytes)
{
    if (!g_metrics) return;
    g_metrics->requests_total++;
    if (status >= 0 && status < 600) g_metrics->requests_by_status[status]++;
    g_metrics->bytes_sent += bytes;
}

void metrics_incr_conn(int delta)
{
    if (!g_metrics) return;
    if (delta > 0) {
        g_metrics->connections_accepted += (uint64_t)delta;
        g_metrics->active_connections  += (uint64_t)delta;
    } else {
        if (g_metrics->active_connections >= (uint64_t)(-delta))
            g_metrics->active_connections -= (uint64_t)(-delta);
    }
}

char *metrics_render_prometheus(size_t *outlen)
{
    if (!g_metrics) { *outlen = 0; return NULL; }
    size_t cap = 8192;
    char *buf = malloc(cap);
    if (!buf) return NULL;
    uint64_t up = time(NULL) - g_metrics->start_time;
    int n = snprintf(buf, cap,
        "# HELP syzygy_requests_total Total requests served\n"
        "# TYPE syzygy_requests_total counter\n"
        "syzygy_requests_total %llu\n"
        "# HELP syzygy_bytes_sent Total bytes sent\n"
        "# TYPE syzygy_bytes_sent counter\n"
        "syzygy_bytes_sent %llu\n"
        "# HELP syzygy_connections_accepted Total connections accepted\n"
        "# TYPE syzygy_connections_accepted counter\n"
        "syzygy_connections_accepted %llu\n"
        "# HELP syzygy_active_connections Current active connections\n"
        "# TYPE syzygy_active_connections gauge\n"
        "syzygy_active_connections %llu\n"
        "# HELP syzygy_cache_hits Cache hits\n"
        "# TYPE syzygy_cache_hits counter\n"
        "syzygy_cache_hits %llu\n"
        "# HELP syzygy_cache_misses Cache misses\n"
        "# TYPE syzygy_cache_misses counter\n"
        "syzygy_cache_misses %llu\n"
        "# HELP syzygy_proxy_requests Proxied requests\n"
        "# TYPE syzygy_proxy_requests counter\n"
        "syzygy_proxy_requests %llu\n"
        "# HELP syzygy_proxy_errors Proxy errors\n"
        "# TYPE syzygy_proxy_errors counter\n"
        "syzygy_proxy_errors %llu\n"
        "# HELP syzygy_circuit_breaker_trips Circuit breaker trips\n"
        "# TYPE syzygy_circuit_breaker_trips counter\n"
        "syzygy_circuit_breaker_trips %llu\n"
        "# HELP syzygy_log_drops Log record drops\n"
        "# TYPE syzygy_log_drops counter\n"
        "syzygy_log_drops %llu\n"
        "# HELP syzygy_uptime_seconds Process uptime\n"
        "# TYPE syzygy_uptime_seconds counter\n"
        "syzygy_uptime_seconds %llu\n"
        "# HELP syzygy_cache_entries Current cache entries\n"
        "# TYPE syzygy_cache_entries gauge\n"
        "syzygy_cache_entries %zu\n"
        "# HELP syzygy_cache_bytes Current cached body bytes\n"
        "# TYPE syzygy_cache_bytes gauge\n"
        "syzygy_cache_bytes %zu\n"
        "# HELP syzygy_upstream_count Configured upstream count\n"
        "# TYPE syzygy_upstream_count gauge\n"
        "syzygy_upstream_count %zu\n",
        (unsigned long long)g_metrics->requests_total,
        (unsigned long long)g_metrics->bytes_sent,
        (unsigned long long)g_metrics->connections_accepted,
        (unsigned long long)g_metrics->active_connections,
        (unsigned long long)g_metrics->cache_hits,
        (unsigned long long)g_metrics->cache_misses,
        (unsigned long long)g_metrics->proxy_requests,
        (unsigned long long)g_metrics->proxy_errors,
        (unsigned long long)g_metrics->cb_trips,
        (unsigned long long)g_metrics->log_drops,
        (unsigned long long)up,
        g_cache.count, g_cache.total_bytes, g_proxy.nups);
    (void)n;
    *outlen = (size_t)n;
    return buf;
}
