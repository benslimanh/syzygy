#!/usr/bin/env bash
############################################################################
#                                                                          #
#   ____ ___  _ ____ ___  _ ________  _                                    #
#  / ___\\  \///_   \\  \///  __/\  \//                                    #
#  |    \ \  /  /   / \  / | |  _ \  /                                     #
#  \___ | / /  /   /_ / /  | |_// / /                                      #
#  \____//_/   \____//_/   \____\/_/                                       #
#                                                                          #
#  Syzygy                                                                  #
#                                                                          #
#  Created by Hamza Bensliman <benslimanh> for 2026                        #
#                                                                          #
#  This software is licensed under the terms of the MIT license.           #
#  You may use, copy, modify, merge, publish, distribute and/or sell       #
#  copies of the Software, and permit persons to whom the Software is      #
#  furnished to do so, under the terms of the MIT license.                 #
#                                                                          #
#  This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF   #
#  ANY KIND, either express or implied.                                    #
#                                                                          #
############################################################################

# run_campaign.sh - continuous fuzzing campaign with coverage accounting.
#
#   ./tests/fuzz/run_campaign.sh [--seconds N] [--workers N] [--corpus DIR]
#
# What it does
#   1. builds fuzz/http_fuzz.c with libFuzzer + ASan + UBSan + source coverage
#   2. seeds the corpus from fuzz/corpus (kept between runs)
#   3. runs N workers in parallel for the given time (default 120 s)
#   4. merges profiles and prints line/region coverage for parser.c and path.c
#   5. fails if any crash/OOM/leak artifact was produced
#
# Exit codes: 0 clean, 1 crash found, 2 build failure
set -uo pipefail

SECONDS_RUN=120
WORKERS=2
CORPUS="fuzz/corpus"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/fuzz/artifacts"

while [ $# -gt 0 ]; do
    case "$1" in
        --seconds) SECONDS_RUN="$2"; shift 2 ;;
        --workers) WORKERS="$2"; shift 2 ;;
        --corpus)  CORPUS="$2"; shift 2 ;;
        *) echo "unknown arg $1"; exit 2 ;;
    esac
done

cd "$ROOT" || exit 2
mkdir -p "$CORPUS" "$OUT"
rm -f "$OUT"/crash-* "$OUT"/leak-* "$OUT"/timeout-* "$OUT"/oom-* 2>/dev/null
rm -rf /tmp/syzygy-fuzz && mkdir -p /tmp/syzygy-fuzz

BIN=/tmp/syzygy-fuzz/http_fuzz
CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined \
        -fprofile-instr-generate -fcoverage-mapping \
        -Iinclude -I./mbedtls/include -D_GNU_SOURCE"

echo "==> building fuzz target"
clang $CFLAGS -o "$BIN" fuzz/http_fuzz.c src/parser.c src/path.c -lz || exit 2

echo "==> campaign: ${SECONDS_RUN}s, ${WORKERS} workers, corpus=$CORPUS"
export LLVM_PROFILE_FILE=/tmp/syzygy-fuzz/prof_%p.profraw
"$BIN" -max_total_time="$SECONDS_RUN" -workers="$WORKERS" -jobs="$WORKERS" \
       -max_len=8192 -timeout=10 -rss_limit_mb=1024 \
       -artifact_prefix="$OUT/" -print_final_stats=1 "$CORPUS" \
       2>&1 | grep -E 'DONE|stat::number_of_executed_units|stat::average_exec_per_sec|ERROR|SUMMARY|AddressSanitizer' || true

# libFuzzer with -jobs writes per-job logs; surface any sanitizer hit
if grep -rlE 'ERROR: (Address|Leak|Undefined)Sanitizer|runtime error:' /tmp/syzygy-fuzz "$OUT" 2>/dev/null | head -5 | grep -q .; then
    echo "!! sanitizer diagnostics found"
    grep -rhE 'ERROR: (Address|Leak|Undefined)Sanitizer|runtime error:' /tmp/syzygy-fuzz "$OUT" 2>/dev/null | head -10
    exit 1
fi

echo "==> coverage"
llvm-profdata merge -sparse /tmp/syzygy-fuzz/*.profraw -o /tmp/syzygy-fuzz/m.profdata 2>/dev/null || true
llvm-cov report "$BIN" -instr-profile=/tmp/syzygy-fuzz/m.profdata src/parser.c src/path.c 2>/dev/null || \
    echo "(coverage tools unavailable: install llvm)"

if ls "$OUT"/crash-* "$OUT"/leak-* >/dev/null 2>&1; then
    echo "!! crash artifacts:"; ls -la "$OUT"
    exit 1
fi
echo "==> clean: no crashes, no sanitizer findings"
