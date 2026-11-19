#!/usr/bin/env bash
# Syft must be installed explicitly (scripts/ci/tools.py syft).
# A binary scan cannot establish a complete distro dependency inventory.
# Release automation also generates an SBOM from the final OCI image.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v syft >/dev/null || { echo 'Syft required; no placeholder SBOM will be generated.' >&2; exit 1; }
temporary=$(mktemp)
trap 'rm -f "$temporary"' EXIT
syft scan file:./syzygy -o "spdx-json=$temporary"
python3 scripts/release/annotate-sbom.py "$temporary"
