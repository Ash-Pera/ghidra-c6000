#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build stacked predicated return windows. Usage: IMAGE [be].

Load at 0x1000 with auto-analysis; C6000StackedReturnWindowsTest.java prepare declares
the functions. Words are TI cl6x 8.3.15 output (-mv6740 --no_compress), listed by dis6x:

  1000 stacked  B t1 || LDW *A4[4],B1 ; NOP ; CMPEQ 0,B4,A1 ; NOP 2 ; [B1] B B3 (the jump's
                last slot; t1 is in sequence) ; t1: [B1] ZERO B0 ; [B1] ZERO A1 ; [A1] B B3 ;
                [B1] STW B0,*A4[4] || [B1] MVK 1,A4 ; [A1] ZERO A4 ; [!A1] B far ; NOP 5
  1038 far      MVK 9,A4 ; B B3 ; NOP 5
  Each return is issued in the window before it on a predicate the earlier one clears
  (SPRUFE8B 3.5, 4.2.6 B): p[4] ? (p[4] = 0, 1) : q == 0 ? 0 : 9
"""

from pathlib import Path
import struct
import sys

WORDS = [
    0x00000313, 0x00908266, 0x00000000, 0x00901A58, 0x00002000, 0x400C0362, 0x40000042, 0x40800040,
    0x800C0362, 0x40108277, 0x420000A8, 0x82000040, 0x90000312, 0x00008000, 0x020004A8, 0x000C0362,
    0x00008000,
]


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x80)
    for index, word in enumerate(WORDS):
        struct.pack_into(endian + "I", image, 4 * index, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
