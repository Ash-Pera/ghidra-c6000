#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Register B to an exact MVK/MVKH constant in an opaque-call schedule (local gate model).
IMAGE CASES.json [be]. Words are TI cl6x 8.3.15 output (-mv6740 --no_compress), no firmware bytes:

  1000 cjin   MVK/MVKH 1020,A0 ; B A0 ; MVK 1,A5 ; NOP 4 ; MVK 0x33,A4 ; B B3 ; NOP 5 ;
              1020: MVK 0x22,A4 ; B B3 ; NOP 5          the target is in the body: a jump
  1100 cjout  MVK/MVKH 1200,A0 ; B A0 ; NOP 5           1200 is outside the body and no function: refused
"""
from pathlib import Path
import json, struct, sys

WORDS = {0x1000: [0x00081028, 0x00000068, 0x00001362, 0x028000A8, 0x00006000, 0x020019A8, 0x000C0362, 0x00008000,
                  0x02001128, 0x000C0362, 0x00008000],
         0x1100: [0x00090028, 0x00000068, 0x00001362, 0x00008000],
         0x1200: [0x02001128, 0x000C0362, 0x00008000]}


def main():
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 4 else "<"
    image = bytearray(0x300)
    for entry, words in WORDS.items():
        for i, w in enumerate(words):
            struct.pack_into(endian + "I", image, entry - 0x1000 + 4 * i, w)
    rows = [dict(name="cjin", entry=0x1000, body=0x30, input={"B3": 0x9000, "A4": 0x4444, "A5": 0},
                 expected={"A4": 0x22, "A5": 1, "PC": 0x9000}),
            dict(name="cjout", entry=0x1100, body=0x10, refused="register branch to a constant that is no function")]
    Path(sys.argv[1]).write_bytes(image)
    Path(sys.argv[2]).write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
