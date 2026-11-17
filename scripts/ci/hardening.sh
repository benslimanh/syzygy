#!/usr/bin/env bash
# Fail closed; do not merely print warnings for missing ELF properties.
set -euo pipefail
binary=${1:-syzygy}
headers=$(readelf -hW "$binary")
program=$(readelf -lW "$binary")
dynamic=$(readelf -dW "$binary")
symbols=$(readelf -sW "$binary")
grep -q 'Type:.*DYN' <<< "$headers"
grep -q GNU_RELRO <<< "$program"
grep -q BIND_NOW <<< "$dynamic"
stack=$(grep GNU_STACK <<< "$program")
[[ "$stack" == *' RW '* && "$stack" != *RWE* ]]
grep -q '__stack_chk_fail' <<< "$symbols"
if nm -D "$binary" | grep -Eq ' U (strcpy|strcat|sprintf|gets)(@|$)'; then
    echo 'Unsafe string function linked' >&2; exit 1
fi
echo 'ELF checks passed: PIE, RELRO/NOW, NX, stack protector, no banned symbols'
