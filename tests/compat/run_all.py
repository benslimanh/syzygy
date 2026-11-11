#!/usr/bin/env python3
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

"""run_all.py - execute the P0 protocol compatibility suite.

Usage:
  python3 tests/compat/run_all.py [--proto h1,h2,tls] [--id H1-001] [--out FILE]
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import harness  # noqa: E402
import test_h1  # noqa: F401,E402  (registers cases)
import test_h2  # noqa: F401,E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--proto", default="")
    ap.add_argument("--id", default="")
    ap.add_argument("--out", default="/tmp/compat-results.json")
    a = ap.parse_args()

    selected = None
    if a.proto:
        protos = {p.strip() for p in a.proto.split(",")}
        selected = {c[0] for c in harness.REGISTRY if c[2] in protos}
    if a.id:
        selected = {a.id} if selected is None else (selected & {a.id})

    results = harness.run(selected=selected, out_json=a.out)
    bad = sum(1 for r in results if r.status in ("fail", "error"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
