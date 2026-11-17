#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p reports/fuzz-corpus reports/fuzz-artifacts
cp fuzz/corpus/* reports/fuzz-corpus/
clang -O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined \
    -fno-sanitize-recover=all -Iinclude -Imbedtls/include -D_GNU_SOURCE \
    -o reports/http_fuzz fuzz/http_fuzz.c src/parser.c src/path.c -lz
reports/http_fuzz -max_total_time=30 -max_len=8192 -timeout=5 \
    -artifact_prefix=reports/fuzz-artifacts/ reports/fuzz-corpus
clang -std=c11 -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined \
    -Iinclude -Imbedtls/include -D_GNU_SOURCE src/*.c \
    mbedtls/library/libmbedtls.a mbedtls/library/libmbedx509.a mbedtls/library/libmbedcrypto.a \
    -lnghttp2 -lssl -lcrypto -lz -ldl -lpthread -rdynamic -o reports/syzygy-asan
SYZYGY_BIN="$PWD/reports/syzygy-asan" "${PYTHON:-.venv/bin/python}" \
    tests/sanitizers/soak.py --duration 60 --workers 2
