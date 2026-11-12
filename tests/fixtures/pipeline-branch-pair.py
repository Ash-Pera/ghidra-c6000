#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Two B in one execute packet on complementary predicates of one register (SPRUFE8B 3.7, B).
IMAGE CASES.json [be]. Words are TI cl6x 8.3.15 output (-mv6740 --no_compress), no firmware bytes:

  1000 prj    [B0] B B3 || [!B0] B 1018 ; MVK 1,A5 ; NOP 4 ; MVK 0x33,A4 ; NOP 5 ; 1018: MVK 0x22,A4 ; B B3 ; NOP 5
  1100 pjr    [A1] B 1118 || [!A1] B B3 ; same body
  1200 prjz   [!B1] B B3 || [B1] B 1218 ; same body
  1300 psame  [B0] B B3 || [B0] B 1314   both may be taken: refused
  1400 pother [B0] B B3 || [!A1] B 1414  two registers: refused
"""
from pathlib import Path
import json, struct, sys

BODY = [0x028000A8, 0x00006000, 0x020019A8, 0x00008000, 0x02001128, 0x000C0362, 0x00008000]
WORDS = {0x1000: [0x200C0363, 0x30000310] + BODY, 0x1100: [0x80000311, 0x900C0362] + BODY,
         0x1200: [0x500C0363, 0x40000310] + BODY,
         0x1300: [0x200C0363, 0x20000290, 0x00008000, 0x000C0362, 0x00008000, 0x000C0362, 0x00008000],
         0x1400: [0x200C0363, 0x90000290, 0x00008000, 0x000C0362, 0x00008000, 0x000C0362, 0x00008000]}


def main():
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 4 else "<"
    image = bytearray(0x500)
    for entry, words in WORDS.items():
        for i, w in enumerate(words):
            struct.pack_into(endian + "I", image, entry - 0x1000 + 4 * i, w)
    rows = []
    for name, entry, reg, returns in [("prj", 0x1000, "B0", lambda v: v != 0), ("pjr", 0x1100, "A1", lambda v: v == 0),
                                      ("prjz", 0x1200, "B1", lambda v: v == 0)]:
        for truth in (0, 1, 0xFFFFFFFF):
            rows.append(dict(name=f"{name}_{truth:x}", entry=entry,
                             input={"B3": 0x9000, "A4": 0x4444, "A5": 0, reg: truth},
                             expected={"A5": 1, "A4": 0x4444 if returns(truth) else 0x22, "PC": 0x9000}))
    rows += [dict(name="psame", entry=0x1300, refused="multiple branches in a packet"),
             dict(name="pother", entry=0x1400, refused="multiple branches in a packet")]
    Path(sys.argv[1]).write_bytes(image)
    Path(sys.argv[2]).write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
