#!/usr/bin/env bash
# Package an already-built binary. Release tags must match the source version.
set -euo pipefail
cd "$(dirname "$0")/../.."
tag=${1:?Usage: package.sh vX.Y.Z [output-directory]}
out=${2:-release-artifacts}
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Expected stable vX.Y.Z tag' >&2; exit 1; }
version=$(sed -n 's/^#define SYZYGY_VERSION[[:space:]]*"\([^"]*\)"/\1/p' include/common.h)
[[ "$tag" == "v$version" ]] || { echo 'Tag does not match SYZYGY_VERSION' >&2; exit 1; }
[[ $(uname -m) == x86_64 ]] || { echo 'Only linux-amd64 packages are supported' >&2; exit 1; }
[[ -x syzygy ]] || { echo 'Build syzygy first' >&2; exit 1; }
mkdir -p "$out"
out=$(realpath "$out")
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
name="syzygy-$version-linux-amd64"
mkdir -p "$stage/$name/bin" "$stage/$name/www"
install -m755 syzygy "$stage/$name/bin/syzygy"
cp -a www/. "$stage/$name/www/"
cp LICENSE README.md deps.lock "$stage/$name/"
python3 - "$stage/$name/build-info.json" <<'PY'
import json, os, platform, subprocess, sys
from pathlib import Path

def run(*args):
    return subprocess.check_output(args, text=True).strip()
info = {'revision': run('git', 'rev-parse', 'HEAD'),
        'mbedtls': run('git', '-C', 'mbedtls', 'rev-parse', 'HEAD'),
        'source_date_epoch': int(os.environ.get('SOURCE_DATE_EPOCH', run('git', 'log', '-1', '--format=%ct'))),
        'architecture': platform.machine(),
        'os_release': Path('/etc/os-release').read_text(),
        'compiler': run(os.environ.get('CC', 'gcc'), '--version').splitlines()[0],
        'dependencies': run('pkg-config', '--modversion', 'libnghttp2', 'openssl', 'zlib').splitlines()}
Path(sys.argv[1]).write_text(json.dumps(info, indent=2) + '\n')
PY
epoch=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
    -C "$stage" -cf - "$name" | gzip -n > "$out/$name.tar.gz"
cp "$stage/$name/build-info.json" "$out/build-info.json"
echo "$out/$name.tar.gz"
