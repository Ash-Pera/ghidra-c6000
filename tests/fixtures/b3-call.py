#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build B B3 calls: B3 holds the target and the slots set it to the return point. Usage: IMAGE [be].

Load at 0x1000 with entry 0x1000 and auto-analysis; C6000B3CallTest.java prepare
declares the four functions, as ELF symbols would. Words are TI cl6x 8.3.15 output
(-mv6740 --no_compress), listed by dis6x (SPRUFE8B 4.2.6, B; upstream issue #39):

  1000 viaptr  STW B3 ; MV A4,B3 ; B B3 ; MVK/MVKH 0x1018,B3 ; NOP 3   fp() + 1: call, returns to 0x1018
       1018    LDW *++B15[2],B3 ; ADD 1,A4,A4 ; NOP 4 ; B B3 ; NOP 5       return
  1040 direct  STW B3 ; MVK/MVKH callee,B3 ; B B3 ; MVK/MVKH 0x105c,B3 ; NOP 3   callee() + 1
       105c    LDW *++B15[2],B3 ; ADD 1,A4,A4 ; NOP 4 ; B B3 ; NOP 5       return
  1080 other   B B3 ; MVK/MVKH callee,B3 ; NOP 4     B3 set elsewhere: a return
  10a0 callee  MVK 41,A4 ; B B3 ; NOP 5
"""

from pathlib import Path
import struct
import sys

WORDS = {
    0x1000: 0x01BC54F6, 0x1004: 0x01901FDA, 0x1008: 0x000C0362, 0x100C: 0x01880C2A,
    0x1010: 0x0180006A, 0x1014: 0x00004000, 0x1018: 0x01BC52E6, 0x101C: 0x02102058,
    0x1020: 0x00006000, 0x1024: 0x000C0362, 0x1028: 0x00008000, 0x1040: 0x01BC54F6,
    0x1044: 0x0188502A, 0x1048: 0x0180006A, 0x104C: 0x000C0362, 0x1050: 0x01882E2A,
    0x1054: 0x0180006A, 0x1058: 0x00004000, 0x105C: 0x01BC52E6, 0x1060: 0x02102058,
    0x1064: 0x00006000, 0x1068: 0x000C0362, 0x106C: 0x00008000, 0x1080: 0x000C0362,
    0x1084: 0x0188502A, 0x1088: 0x0180006A, 0x108C: 0x00006000, 0x10A0: 0x020014A8,
    0x10A4: 0x000C0362, 0x10A8: 0x00008000,
}


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0xc0)
    for address, word in WORDS.items():
        struct.pack_into(endian + "I", image, address - 0x1000, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
