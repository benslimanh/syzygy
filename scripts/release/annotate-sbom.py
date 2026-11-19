#!/usr/bin/env python3
"""Add a manifest-derived static TLS component to Syft's discovered inventory.

Syft cannot reliably discover statically linked C dependencies. This explicit
annotation identifies its source and is not presented as scanner discovery.
"""
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]


def annotate(document, version, commit):
    identifier = 'SPDXRef-Vendored-mbedtls'
    if any(p['SPDXID'] == identifier for p in document['packages']):
        raise ValueError('vendored component is already annotated')
    document['packages'].append({
        'name': 'mbedtls', 'SPDXID': identifier, 'versionInfo': version,
        'downloadLocation': f'git+https://github.com/Mbed-TLS/mbedtls.git@{commit}',
        'filesAnalyzed': False, 'licenseConcluded': 'NOASSERTION',
        'licenseDeclared': 'NOASSERTION', 'copyrightText': 'NOASSERTION',
        'sourceInfo': f'Manifest-derived static dependency from deps.lock; git commit {commit}. Not inferred by Syft.',
        'externalRefs': [{'referenceCategory': 'PACKAGE-MANAGER',
                          'referenceType': 'purl',
                          'referenceLocator': f'pkg:github/Mbed-TLS/mbedtls@{commit}'}]})
    roots = [r['relatedSpdxElement'] for r in document.get('relationships', [])
             if r['spdxElementId'] == 'SPDXRef-DOCUMENT' and r['relationshipType'] == 'DESCRIBES']
    if not roots:
        raise ValueError('SBOM has no described subject')
    document['relationships'].append({'spdxElementId': roots[0],
                                      'relationshipType': 'CONTAINS',
                                      'relatedSpdxElement': identifier})
    return document


if __name__ == '__main__':
    source = Path(sys.argv[1])
    lock = (ROOT / 'deps.lock').read_text()
    commit = re.search(r'^mbedtls_commit=([a-f0-9]{40})$', lock, re.M).group(1)
    version = re.search(r'^#define MBEDTLS_VERSION_STRING\s+"([^"]+)"',
                        (ROOT / 'mbedtls/include/mbedtls/build_info.h').read_text(), re.M).group(1)
    document = annotate(json.loads(source.read_text()), version, commit)
    output = json.dumps(document, indent=2) + '\n'
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text(output)
    else:
        print(output, end='')
