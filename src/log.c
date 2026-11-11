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
 * log.c - Async structured logging.
 *
 * Supports three backends:
 *   - stderr (default)
 *   - log file (re-openable for rotation via SIGUSR1 / -l <path>)
 *   - syslog (LOG_DAEMON by default)
 * Lines are pushed through a per-worker SPSC ring buffer; if the ring
 * fills we count drops via metrics and the line is sent directly to
 * the backend as a best-effort fallback.
 */
#include "log.h"
#include "metrics.h"
#include <pthread.h>
#include <stdatomic.h>
#include <syslog.h>
#include <fcntl.h>

static int          g_log_fd = 2;
static bool         g_log_fd_owned = false;   /* opened via log_set_file */
static ringbuf_t   *g_log_ring;
static atomic_bool  g_log_json;
static atomic_bool  g_log_use_syslog;
static volatile bool g_log_stop;
static char         g_log_path[SYZYGY_PATH_MAX];

void log_set_json(bool on) { atomic_store(&g_log_json, on); }

__attribute__((constructor)) static void _log_init(void)
{
    atomic_init(&g_log_json, false);
    atomic_init(&g_log_use_syslog, false);
    g_log_fd = 2;
    g_log_fd_owned = false;
    g_log_path[0] = '\0';
}

void log_init_async(int fd, ringbuf_t *shared_ring)
{
    if (fd >= 0) {
        if (g_log_fd_owned && g_log_fd > 2) close(g_log_fd);
        g_log_fd = fd;
        g_log_fd_owned = false;
    }
    g_log_ring = shared_ring;
}

void log_set_syslog(const char *ident, int facility)
{
    /* If facility is -1 pick a reasonable default */
    if (facility <= 0) facility = LOG_DAEMON;
    openlog(ident ? ident : "syzygy", LOG_PID | LOG_NDELAY, facility);
    atomic_store(&g_log_use_syslog, true);
}

void log_set_file(const char *path)
{
    int nfd = 2;
    if (path && path[0]) {
        nfd = open(path, O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC|O_NONBLOCK, 0644);
        if (nfd < 0) {
            /* Fall back to stderr on failure */
            nfd = 2;
            path = NULL;
        }
    }
    if (g_log_fd_owned && g_log_fd > 2) close(g_log_fd);
    g_log_fd = nfd;
    g_log_fd_owned = (nfd > 2);
    if (path) {
        size_t L = strlen(path);
        if (L >= sizeof g_log_path) L = sizeof g_log_path - 1;
        memcpy(g_log_path, path, L); g_log_path[L] = '\0';
    } else {
        g_log_path[0] = '\0';
    }
}

void log_shutdown(void)
{
    g_log_stop = true;
    if (atomic_load_explicit(&g_log_use_syslog, memory_order_relaxed)) {
        closelog();
    }
    if (g_log_fd_owned && g_log_fd > 2) {
        close(g_log_fd); g_log_fd = 2; g_log_fd_owned = false;
    }
}

static void write_backend(int level, const char *buf, size_t len)
{
    /* Syslog */
    if (atomic_load_explicit(&g_log_use_syslog, memory_order_relaxed)) {
        int pri = LOG_INFO;
        switch (level) {
            case LOG_EMERG: pri = LOG_EMERG; break;
            case LOG_ALERT: pri = LOG_ALERT; break;
            case LOG_CRIT:  pri = LOG_CRIT; break;
            case LOG_ERR:   pri = LOG_ERR; break;
            case LOG_WARN:  pri = LOG_WARNING; break;
            case LOG_NOTICE:pri = LOG_NOTICE; break;
            case LOG_INFO:  pri = LOG_INFO; break;
            case LOG_DEBUG: pri = LOG_DEBUG; break;
        }
        syslog(pri, "%.*s", (int)len, buf);
    }
    /* Also write to fd (stderr or log file). If syslog is the only
     * desired backend users can close/redirect stderr in systemd. */
    if (g_log_fd >= 0) {
        (void)!write(g_log_fd, buf, len);
    }
}

static void enqueue_line(int level, const char *buf, size_t len)
{
    if (!g_log_ring) {
        write_backend(level, buf, len);
        return;
    }
    size_t n = ringbuf_write(g_log_ring, buf, len);
    if (n < len) {
        if (g_metrics) g_metrics->log_drops++;
        write_backend(level, buf, len); /* fallback direct */
    }
}

void log_emit(int level, int worker_id, const char *remote,
              const char *method, const char *path, int status,
              size_t bytes, uint64_t duration_us)
{
    char tbuf[128];
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);
    int tl = snprintf(tbuf, sizeof tbuf,
                      "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
                      tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
                      tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec/1000000);
    (void)tl;

    /* Sanitise the request target: control characters would allow log
     * injection (a URI containing "\n" forges a second access-log line). */
    char safe_path[256];
    size_t sp_len = 0;
    if (path) {
        for (const char *q = path; *q && sp_len < sizeof safe_path - 1; q++) {
            unsigned char ch = (unsigned char)*q;
            safe_path[sp_len++] = (ch < 0x20 || ch == 0x7f) ? '?' : (char)ch;
        }
    }
    safe_path[sp_len] = '\0';
    const char *log_path = path ? safe_path : "-";

    char line[1024]; int n;
    if (atomic_load_explicit(&g_log_json, memory_order_relaxed)) {
        n = snprintf(line, sizeof line,
            "{\"ts\":\"%s\",\"lvl\":%d,\"w\":%d,\"r\":\"%s\","
            "\"m\":\"%s\",\"p\":\"%s\",\"s\":%d,\"b\":%zu,\"us\":%llu}\n",
            tbuf, level, worker_id, remote ? remote : "-",
            method ? method : "-", log_path,
            status, bytes, (unsigned long long)duration_us);
    } else {
        n = snprintf(line, sizeof line,
            "%s [%d] w=%d r=%s m=%s p=%s s=%d b=%zu us=%llu\n",
            tbuf, level, worker_id, remote ? remote : "-",
            method ? method : "-", log_path,
            status, bytes, (unsigned long long)duration_us);
    }
    /* snprintf() returns the length it *would* have written; `line` only
     * holds sizeof line bytes. Using n verbatim made every request with a
     * URI longer than ~900 bytes copy stack memory into the access log. */
    if (n > 0) {
        if ((size_t)n >= sizeof line - 1) {
            /* Truncated: snprintf() dropped the trailing '\n'. Keep the
             * record newline-terminated so the log stays line-oriented. */
            n = (int)sizeof line - 2;
            line[n++] = '\n';
        }
        enqueue_line(level, line, (size_t)n);
    }
}

void log_emit_plain(int level, const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n > 0) {
        if ((size_t)n >= sizeof buf) n = sizeof buf - 1;
        buf[n++] = '\n';
        enqueue_line(level, buf, (size_t)n);
    }
}

/* Called from the worker drain loop to flush ring contents to backend */
void log_drain_to_backend(ringbuf_t *r)
{
    char tmp[16384];
    for (;;) {
        size_t n = ringbuf_read(r, tmp, sizeof tmp);
        if (n == 0) break;
        /* Lines in the ring were enqueued with level embedded in JSON;
         * use LOG_INFO as a safe default for draining. */
        write_backend(LOG_INFO, tmp, n);
    }
}
