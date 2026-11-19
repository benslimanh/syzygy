#!/usr/bin/env python3
"""Install reviewed Linux amd64 tools; verify the committed digest before use.

Usage: python3 scripts/ci/tools.py actionlint helm ...
No remote installer scripts, implicit latest versions, or tar extractall.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import sys
import tarfile
import urllib.request


def verified_binary(data, spec):
    if hashlib.sha256(data).hexdigest() != spec['sha256']:
        raise ValueError('download checksum mismatch')
    if not spec['member']:
        return data
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        member = archive.getmember(spec['member'])
        if not member.isfile():
            raise ValueError('expected a regular executable in archive')
        return archive.extractfile(member).read()


def main():
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'amd64'):
        raise SystemExit('Tool lock currently supports Linux amd64 only.')
    lock = json.loads(Path(__file__).with_name('tools.lock.json').read_text())
    names = sys.argv[1:]
    if not names or any(name not in lock for name in names):
        raise SystemExit('Choose tools: ' + ', '.join(sorted(lock)))
    dest = Path(os.environ.get('TOOLS_DIR', '.tools/bin')).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    for name in names:
        spec = lock[name]
        if not spec['url'].startswith('https://'):
            raise ValueError('HTTPS required')
        with urllib.request.urlopen(spec['url'], timeout=120) as response:
            data = response.read()
        binary = verified_binary(data, spec)
        temporary = dest / (name + '.tmp')
        temporary.write_bytes(binary)
        temporary.chmod(0o755)
        temporary.replace(dest / name)
        print(f'{name} {spec["version"]}: checksum verified -> {dest / name}')
    if os.environ.get('GITHUB_PATH'):
        with open(os.environ['GITHUB_PATH'], 'a') as path_file:
            path_file.write(str(dest) + '\n')


if __name__ == '__main__':
    main()
