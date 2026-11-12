#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SAT phase contract: .L, E1 read of the 40-bit pair, dst and CSR.SAT in E1 (SPRUFE8B SAT).
IMAGE CASES.json [be]. Words are TI cl6x 8.3.15 output (-mv6740 --no_compress), no firmware bytes:

  1000 sat1  SAT .L1 A5:A4,A6 || MV .S1 A6,A8 ; MV .S1 A6,A9 ; B B3 ; NOP 5
  1040 sat2  SAT .L2 B5:B4,B6 || MV .S2 B6,B8 ; MV .S2 B6,B9 ; B B3 ; NOP 5
  1080 satp  [B0] SAT .L1 A5:A4,A6 ; MV .S1 A6,A9 ; B B3 ; NOP 5
"""
from pathlib import Path
import json, struct, sys

TAIL = [0x000C0362, 0x00008000]
WORDS = {0x1000: [0x03100819, 0x041806A0, 0x049806A0] + TAIL, 0x1040: [0x0310081B, 0x041806A2, 0x049806A2] + TAIL,
         0x1080: [0x23100818, 0x049806A0] + TAIL}
OLD, CSR = 0x13579BDF, 0x00000100


def sat(hi, lo):
    v = (hi & 0xFF) << 32 | lo
    v -= (1 << 40) if v >> 39 else 0
    if v > 0x7FFFFFFF: return 0x7FFFFFFF, True
    if v < -0x80000000: return 0x80000000, True
    return v & 0xFFFFFFFF, False


def main():
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 4 else "<"
    image = bytearray(0x100)
    for entry, words in WORDS.items():
        for i, w in enumerate(words):
            struct.pack_into(endian + "I", image, entry - 0x1000 + 4 * i, w)
    pairs = [(0, 0x12345678), (0xFF, 0x80000000), (0x12345600, 0x7FFFFFFF), (1, 0), (0xFE, 0), (0x7F, 0xFFFFFFFF), (0x80, 0)]
    rows = []
    for hi, lo in pairs:
        value, saturated = sat(hi, lo)
        csr = CSR | (0x200 if saturated else 0)
        for name, entry, bank in (("sat1", 0x1000, "A"), ("sat2", 0x1040, "B")):
            rows.append(dict(name=f"{name}_{hi:x}_{lo:x}", entry=entry,
                             input={"B3": 0x9000, "CSR": CSR, f"{bank}5": hi, f"{bank}4": lo, f"{bank}6": OLD},
                             expected={f"{bank}6": value, f"{bank}8": OLD, f"{bank}9": value, "CSR": csr, "PC": 0x9000}))
        for truth in (0, 1):
            rows.append(dict(name=f"satp_{truth}_{hi:x}_{lo:x}", entry=0x1080,
                             input={"B3": 0x9000, "CSR": CSR, "A5": hi, "A4": lo, "A6": OLD, "B0": truth},
                             expected={"A6": value if truth else OLD, "A9": value if truth else OLD,
                                       "CSR": csr if truth else CSR, "PC": 0x9000}))
    Path(sys.argv[1]).write_bytes(image)
    Path(sys.argv[2]).write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
