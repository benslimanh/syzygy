#!/usr/bin/env python3
"""Create a stable checksum manifest without hashing itself or its signature."""
import hashlib
from pathlib import Path
import sys


def write_checksums(directory):
    directory = Path(directory)
    files = sorted(path for path in directory.iterdir()
                   if path.name not in ('SHA256SUMS', 'SHA256SUMS.sigstore.json'))
    if not files:
        raise ValueError('no release files to hash')
    lines = []
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise ValueError('release assets must be regular files')
        if any(c in path.name for c in '\n\r\\'):
            raise ValueError('unsafe asset name')
        lines.append(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n')
    (directory / 'SHA256SUMS').write_text(''.join(lines))


if __name__ == '__main__':
    write_checksums(sys.argv[1])
