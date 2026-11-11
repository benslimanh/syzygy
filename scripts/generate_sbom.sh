#!/usr/bin/env bash
############################################################################
#                                                                          #
#   ____ ___  _ ____ ___  _ ________  _                                    #
#  / ___\\  \///_   \\  \///  __/\  \//                                    #
#  |    \ \  /  /   / \  / | |  _ \  /                                     #
#  \___ | / /  /   /_ / /  | |_// / /                                      #
#  \____//_/   \____//_/   \____\/_/                                       #
#                                                                          #
#  Syzygy                                                                  #
#                                                                          #
#  Created by Hamza Bensliman <benslimanh> for 2026                        #
#                                                                          #
#  This software is licensed under the terms of the MIT license.           #
#  You may use, copy, modify, merge, publish, distribute and/or sell       #
#  copies of the Software, and permit persons to whom the Software is      #
#  furnished to do so, under the terms of the MIT license.                 #
#                                                                          #
#  This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF   #
#  ANY KIND, either express or implied.                                    #
#                                                                          #
############################################################################

# SPDX SBOM stub generator. For a real SBOM, install 'syft' or 'spdx-sbom-generator':
#   syft binary:./syzygy -o spdx-json=syzygy.spdx.json
set -euo pipefail
ver=$(grep -oP 'SYZYGY_VERSION\s+"\K[^"]+' include/common.h)
cat <<EOF
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: syzygy-${ver}
DocumentNamespace: https://syzygy.example/spdx/${ver}
Creator: Tool: syzygy-make-sbom
Created: $(date -u +%Y-%m-%dT%H:%M:%SZ)

PackageName: syzygy
SPDXID: SPDXRef-Package-syzygy
PackageVersion: ${ver}
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
PackageLicenseConcluded: MIT
PackageLicenseDeclared: MIT
PackageCopyrightText: NOASSERTION
PackageSupplier: Organization: syzygy contributors
EOF
