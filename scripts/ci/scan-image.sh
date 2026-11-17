#!/usr/bin/env bash
# A scanner returning success with no supported inventory is not a clean scan.
set -euo pipefail
archive=${1:?Usage: scan-image.sh image.docker.tar [report.json]}
report=${2:-reports/image-vulnerabilities.json}
mkdir -p "$(dirname "$report")"
trivy image --input "$archive" --scanners vuln --exit-code 1 \
    --severity HIGH,CRITICAL --list-all-pkgs --format json --output "$report"
python3 - "$report" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
if report.get('Metadata', {}).get('OS', {}).get('Family') != 'debian':
    raise SystemExit('Expected Debian runtime inventory; scan coverage is missing')
packages = [p for r in report.get('Results', []) for p in r.get('Packages', [])]
if not {'libc6', 'libnghttp2-14', 'zlib1g'} <= {p['Name'] for p in packages}:
    raise SystemExit('Missing runtime library inventory; refusing a false-green scan')
print(f'Image scan passed with {len(packages)} inventoried distro packages')
PY
