#!/usr/bin/env bash
# Build the full vendored TLS + application twice in different clean paths.
# This proves reproducibility within this toolchain/library environment, not
# hermetic reproducibility across arbitrary distros or dependency updates.
set -euo pipefail
cd "$(dirname "$0")/../.."
root=$PWD
if ! git diff --quiet || ! git diff --cached --quiet; then
    echo 'Commit tracked changes before checking reproducibility (builds use HEAD).' >&2
    exit 1
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
export LC_ALL=C TZ=UTC
for name in first second; do
    dest="$work/$name"
    mkdir -p "$dest/mbedtls"
    git archive HEAD | tar -x -C "$dest"
    git -C mbedtls archive HEAD | tar -x -C "$dest/mbedtls"
    mkdir -p "$dest/mbedtls/framework"
    git -C mbedtls/framework archive HEAD | tar -x -C "$dest/mbedtls/framework"
    (
        cd "$dest"
        make -C mbedtls -j"${JOBS:-2}" CC="${CC:-gcc}" \
            CFLAGS="-O2 -fPIC -ffile-prefix-map=$dest=/src" lib
        make -j"${JOBS:-2}" CC="${CC:-gcc}" all
    ) > "$work/$name.log" 2>&1 || { tail -100 "$work/$name.log"; exit 1; }
done
cmp "$work/first/syzygy" "$work/second/syzygy"
mkdir -p "$root/reports"
sha256sum "$work/first/syzygy" | awk '{print $1}' > "$root/reports/repro.sha256"
printf 'Reproducible in two clean build paths: %s\n' "$(cat "$root/reports/repro.sha256")"
