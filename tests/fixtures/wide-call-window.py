#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build a B call whose five delay cycles hold 30 instructions. Usage: IMAGE [be].

Load at 0x1000 with entry 0x1000 and auto-analysis; C6000WideCallWindowTest.java
prepare declares the two functions, as ELF symbols would. Words are TI cl6x
8.3.15 output (-mv6740 --no_compress), listed by dis6x (SPRUFE8B 3.5, 4.2.6):

  1000 wide    STW B3,*B15--[2] ; B.S1 callee
       1008    five execute packets of six ADD/MVKL/MVKH (A4, B4, B5, A6, B6, A7);
               MVKL/MVKH 0x1080,B3 in the third and fourth: a call returning to 0x1080
       1080    LDW *++B15[2],B3 ; ADD 1,A4,A4 ; NOP 4 ; B B3 ; ADD 1,A4,A4 ; NOP 4
  10a0 callee  ADD A4,A6,A4 ; B B3 ; NOP 5
"""

from pathlib import Path
import struct
import sys

WORDS = {
    0x1000: 0x01BC54F6, 0x1004: 0x00001410, 0x1008: 0x02102059, 0x100C: 0x0210205B,
    0x1010: 0x029421A3, 0x1014: 0x03182941, 0x1018: 0x03182943, 0x101C: 0x039C21A0,
    0x1020: 0x02102059, 0x1024: 0x0210205B, 0x1028: 0x029421A3, 0x102C: 0x03182941,
    0x1030: 0x03182943, 0x1034: 0x039C21A0, 0x1038: 0x02102059, 0x103C: 0x0210205B,
    0x1040: 0x0188402B, 0x1044: 0x03182941, 0x1048: 0x03182943, 0x104C: 0x039C21A0,
    0x1050: 0x02102059, 0x1054: 0x0210205B, 0x1058: 0x0180006B, 0x105C: 0x03182941,
    0x1060: 0x03182943, 0x1064: 0x039C21A0, 0x1068: 0x02102059, 0x106C: 0x0210205B,
    0x1070: 0x029421A3, 0x1074: 0x03182941, 0x1078: 0x03182943, 0x107C: 0x039C21A0,
    0x1080: 0x01BC52E6, 0x1084: 0x02102058, 0x1088: 0x00006000, 0x108C: 0x000C0362,
    0x1090: 0x02102058, 0x1094: 0x00006000, 0x10A0: 0x02188078, 0x10A4: 0x000C0362,
    0x10A8: 0x00008000,
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
