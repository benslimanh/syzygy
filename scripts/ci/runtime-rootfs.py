#!/usr/bin/env python3
"""Assemble a shell-free runtime from this Debian build's actual ELF closure.

Preserve dpkg metadata for every copied shared-library package so vulnerability
scanners do not lose the inventory when the final stage uses FROM scratch.
Run only on our just-built, trusted binary (ldd is not safe on arbitrary input).
"""
from pathlib import Path
import re
import shutil
import subprocess
import sys


def run(*args):
    return subprocess.check_output(args, text=True)


def main():
    binary = Path(sys.argv[1]).resolve()
    dest = Path(sys.argv[2]).resolve()
    listing = run('ldd', str(binary))
    if 'not found' in listing:
        raise ValueError('unresolved runtime dependency')
    libraries = sorted(set(re.findall(r'(/[^\s()]+)', listing)))
    if not libraries:
        raise ValueError('expected a dynamically linked application')
    packages = {'ca-certificates'}
    for name in libraries:
        source = Path(name)
        target = dest / source.relative_to('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target, follow_symlinks=True)
        owner = run('dpkg-query', '-S', str(source.resolve())).splitlines()[0]
        packages.add(owner.split(': /', 1)[0])
    for source in ['/etc/os-release', '/etc/debian_version', '/etc/ssl/certs/ca-certificates.crt']:
        target = dest / Path(source).relative_to('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target, follow_symlinks=True)
    (dest / 'etc/passwd').write_text('nobody:x:65532:65532:nonroot:/:/sbin/nologin\n')
    (dest / 'etc/group').write_text('nogroup:x:65532:\n')
    (dest / 'etc/nsswitch.conf').write_text('hosts: files dns\npasswd: files\ngroup: files\n')
    (dest / 'tmp').mkdir(exist_ok=True)
    (dest / 'tmp').chmod(0o1777)
    metadata = dest / 'var/lib/dpkg/status'
    metadata.parent.mkdir(parents=True, exist_ok=True)
    metadata.write_text('\n\n'.join(run('dpkg-query', '-s', name).strip() for name in sorted(packages)) + '\n')
    target = dest / 'usr/local/bin/syzygy'
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(binary, target)
    print('Runtime library package inventory:', ', '.join(sorted(packages)))


if __name__ == '__main__':
    main()
