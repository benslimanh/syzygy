#!/usr/bin/env bash
set -euo pipefail
tag=${1:?Expected release tag}
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Stable vX.Y.Z tag required' >&2; exit 1; }
version=$(sed -n 's/^#define SYZYGY_VERSION[[:space:]]*"\([^"]*\)"/\1/p' include/common.h)
[[ "$tag" == "v$version" ]] || { echo 'Version/tag mismatch' >&2; exit 1; }
[[ $(git rev-parse "$tag^{commit}") == "$(git rev-parse HEAD)" ]]
git merge-base --is-ancestor HEAD origin/main || {
    echo 'Release commit must be reachable from origin/main' >&2; exit 1;
}
