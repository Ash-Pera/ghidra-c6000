#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build branches through a copy of B3. Usage: IMAGE [be].

Load at 0x1000 with entry 0x1000 and auto-analysis; C6000LinkCopyReturnTest.java
prepare declares the five functions, as ELF symbols would. Words are TI cl6x
8.3.15 output (-mv6740 --no_compress), listed by dis6x (SPRUFE8B 4.2.6, B, MV):

  1000 copyret  MV B3,B9 ; ADD 1,A4,A4 ; NOP ; B B9 ; ADD 1,A4,A4 ; NOP 4   return a + 2
  1020 addret   ADD 0,B3,B9 (dis6x MV.D2) ; B B9 ; ADD 3,A4,A4 ; NOP 4      return a + 3
  1040 notb3    MV B4,B9 ; B B9 ; NOP 5                  B9 is not the link: not a return
  1060 twowr    MV B3,B9 ; [A1] MV B4,B9 ; B B9 ; NOP 5  B9 written twice: not a return
  1080 stale    MVK/MVKH twowr,B3 ; MV B3,B9 ; B B9 ; NOP 5   B3 rewritten first: not a return
"""

from pathlib import Path
import struct
import sys

WORDS = {
    0x1000: 0x048C06A2, 0x1004: 0x02102058, 0x100C: 0x00240362, 0x1010: 0x02102058,
    0x1014: 0x00006000, 0x1020: 0x048C0942, 0x1024: 0x00240362, 0x1028: 0x02106058,
    0x102C: 0x00006000, 0x1040: 0x049006A2, 0x1044: 0x00240362, 0x1048: 0x00008000,
    0x1060: 0x048C06A2, 0x1064: 0x849006A2, 0x1068: 0x00240362, 0x106C: 0x00008000,
    0x1080: 0x0188302A, 0x1084: 0x0180006A, 0x1088: 0x048C06A2, 0x108C: 0x00240362,
    0x1090: 0x00008000,
}


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0xa0)
    for address, word in WORDS.items():
        struct.pack_into(endian + "I", image, address - 0x1000, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
