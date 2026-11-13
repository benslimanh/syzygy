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

/* Resolve relative to pinned directory descriptors. Every URI component is
 * opened with O_NOFOLLOW; callers serve the returned descriptor instead of
 * re-opening a pathname after validation. The output path is metadata only.
 * Hard links and files deliberately placed in the root remain administrator
 * responsibilities; O_NOFOLLOW is a symlink policy, not a hard-link sandbox.
 */
#include "common.h"

static const char *index_files[] = { "index.html", "index.htm", NULL };

int safe_open_path(const char *root, const char *uri_path, size_t uri_plen,
                   char *out, size_t out_sz, struct stat *st_out, bool *is_dir)
{
    if (!root || !uri_path || !out || out_sz < SYZYGY_PATH_MAX ||
        !uri_plen || uri_path[0] != '/') return -1;
    size_t root_len = strnlen(root, SYZYGY_PATH_MAX);
    if (!root_len || root_len >= SYZYGY_PATH_MAX - 8) return -1;
    memcpy(out, root, root_len);
    if (out[root_len - 1] != '/') out[root_len++] = '/';
    size_t pos = root_len;
    out[pos] = '\0';

    /* The configured root is trusted; never follow URI-supplied symlinks. */
    int fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return -1;
    struct stat st;
    size_t i = 1;
    while (i < uri_plen) {
        if (uri_path[i] == '/') { i++; continue; }
        size_t start = i;
        while (i < uri_plen && uri_path[i] != '/') {
            unsigned char ch = (unsigned char)uri_path[i];
            if (ch < 0x20 || ch == 0x7f || ch == '\\' ||
                (ch == '%' && i + 2 < uri_plen &&
                 uri_path[i+1] == '0' && uri_path[i+2] == '0')) goto fail;
            i++;
        }
        size_t n = i - start;
        if (n > 255 || (n == 1 && uri_path[start] == '.') ||
            (n == 2 && uri_path[start] == '.' && uri_path[start+1] == '.')) goto fail;
        char name[256];
        memcpy(name, uri_path + start, n); name[n] = '\0';
        size_t next = i;
        while (next < uri_plen && uri_path[next] == '/') next++;
        int flags = O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;
        if (next < uri_plen || i < uri_plen) flags |= O_DIRECTORY;
        int child = openat(fd, name, flags);
        if (child < 0) goto fail;
        close(fd); fd = child;
        if (pos > root_len) {
            if (pos + 1 >= out_sz) goto fail;
            out[pos++] = '/';
        }
        if (pos + n >= out_sz) goto fail;
        memcpy(out + pos, name, n); pos += n; out[pos] = '\0';
        i = next;
    }
    if (fstat(fd, &st) < 0) goto fail;
    if (S_ISDIR(st.st_mode)) {
        for (int j = 0; index_files[j]; j++) {
            size_t n = strlen(index_files[j]);
            if (pos + 1 + n >= out_sz) continue;
            int idx = openat(fd, index_files[j],
                             O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
            if (idx < 0) continue;
            struct stat ist;
            if (fstat(idx, &ist) == 0 && S_ISREG(ist.st_mode)) {
                close(fd); fd = idx; st = ist;
                out[pos++] = '/';
                memcpy(out + pos, index_files[j], n + 1);
                break;
            }
            close(idx);
        }
    }
    if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)) goto fail;
    if (st_out) *st_out = st;
    if (is_dir) *is_dir = S_ISDIR(st.st_mode);
    return fd;
fail:
    close(fd);
    return -1;
}

/* Metadata-only compatibility helper for tests and fuzzers. Serving code
 * must use safe_open_path and retain its descriptor through transmission. */
int safe_resolve_path(const char *root, const char *uri_path, size_t uri_plen,
                      char *out, size_t out_sz, struct stat *st_out, bool *is_dir)
{
    int fd = safe_open_path(root, uri_path, uri_plen, out, out_sz, st_out, is_dir);
    if (fd < 0) return -1;
    close(fd);
    return 0;
}
