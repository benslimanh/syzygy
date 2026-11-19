#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
python=${PYTHON:-.venv/bin/python}
[[ -x "$python" ]] || { echo 'Create .venv and install tests/requirements.lock first.' >&2; exit 1; }
mkdir -p reports
make test mod certs
"$python" -m unittest discover -s tests/ops -v
"$python" tests/compat/run_all.py --out "$PWD/reports/compat.json"
"$python" tests/regression/track1.py --out "$PWD/reports/track1.json"
"$python" tests/regression/path_confinement.py
"$python" tests/regression/module_protocol.py
bash tests/security_fixes.sh
bash scripts/ci/hardening.sh syzygy
