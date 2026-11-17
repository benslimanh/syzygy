#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${CC:=gcc}"
export CC
expected=$(sed -n 's/^mbedtls_commit=//p' deps.lock)
[[ $(git -C mbedtls rev-parse HEAD) == "$expected" ]] || {
    echo 'mbedTLS does not match deps.lock; run git submodule update --init --recursive' >&2
    exit 1
}
[[ -z $(git -C mbedtls status --porcelain --untracked-files=no) ]] || {
    echo 'Tracked mbedTLS sources were modified.' >&2; exit 1;
}
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
export LC_ALL=C TZ=UTC
jobs=${JOBS:-2}
make -C mbedtls clean
make clean
make -C mbedtls -j"$jobs" CC="$CC" CFLAGS="-O2 -fPIC -ffile-prefix-map=$PWD=/src" lib
make -j"$jobs" CC="$CC" all
