#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The CI decode/p-code smoke packet. Usage: IMAGE [be]."""
from pathlib import Path
import struct
import sys

words = [0x07ad7e2a, 0x0788c06a, 0x07bf09f2, 0x0734802a,
         0x0708c06a, 0x0200a35a, 0x091003a2, 0x0a1003a2,
         0x0221402a, 0x0208c06a, 0x00100362, 0x28802d2a]
if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
    raise SystemExit(__doc__)
Path(sys.argv[1]).write_bytes(struct.pack((">" if len(sys.argv) == 3 else "<") + "12I", *words))
