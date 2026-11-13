#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build calls issued in a jump's window whose link the jump's target code sets. Usage: IMAGE [be].

Load at 0x1000 with auto-analysis; C6000JumpTailTest.java prepare declares
the functions, as ELF symbols would. Words are TI cl6x 8.3.15 output (-mv6740
--abi=eabi --no_compress), listed by dis6x. The call issues in cycle 3 of the
jump's window and lands 3 cycles after the jump, so the target code first sets
B3 to the point it has run to (SPRUFE8B 3.5, 4.2.6 B):

  1000 jtail      MV B3,B13 || MV A4,A1 ; [A1] B t7 ; NOP 2 ; [A1] B callee ; NOP 2 ;
                  MVK 7,A4 ; MV B13,B3 ; B B3 ; NOP 5 ; t7: MVKL r7,B3 ; MVKH r7,B3 ;
                  MV B4,A4 ; r7: ADDK 16,A4 ; MV B13,B3 ; B B3 ; NOP 5.
                  a ? callee(b) + 16 : 7
  1160 callee     B B3 ; ADD A4,A4,A4 ; NOP 4
  Known-bads, no carried call:
  1060 jtailent   [B0] B t8 enters the tail code too, where no call is pending
  10c0 jtaillink  the target code sets B3 one instruction past where the call lands
  1120 jtailfall  not taken, MVK 7,A4 falls into the tail code, where no call is pending
"""

from pathlib import Path
import struct
import sys

WORDS = {
    0x1000: 0x068C0FDB, 0x1004: 0x00900FD8, 0x1008: 0x80000510, 0x100C: 0x00002000,
    0x1010: 0x80002C12, 0x1014: 0x00002000, 0x1018: 0x020003A8, 0x101C: 0x01B40FDA,
    0x1020: 0x000C0362, 0x1024: 0x00008000, 0x1028: 0x01881A2A, 0x102C: 0x0180006A,
    0x1030: 0x02101FD8, 0x1034: 0x02000850, 0x1038: 0x01B40FDA, 0x103C: 0x000C0362,
    0x1040: 0x00008000, 0x1060: 0x068C0FDB, 0x1064: 0x00900FD9, 0x1068: 0x001808F2,
    0x106C: 0x20000690, 0x1070: 0x00008000, 0x1074: 0x80000690, 0x1078: 0x00002000,
    0x107C: 0x80002012, 0x1080: 0x00002000, 0x1084: 0x020003A8, 0x1088: 0x01B40FDA,
    0x108C: 0x000C0362, 0x1090: 0x00008000, 0x1094: 0x0188502A, 0x1098: 0x0180006A,
    0x109C: 0x02101FD8, 0x10A0: 0x02000850, 0x10A4: 0x01B40FDA, 0x10A8: 0x000C0362,
    0x10AC: 0x00008000, 0x10C0: 0x068C0FDB, 0x10C4: 0x00900FD8, 0x10C8: 0x80000510,
    0x10CC: 0x00002000, 0x10D0: 0x80001412, 0x10D4: 0x00002000, 0x10D8: 0x020003A8,
    0x10DC: 0x01B40FDA, 0x10E0: 0x000C0362, 0x10E4: 0x00008000, 0x10E8: 0x01887C2A,
    0x10EC: 0x0180006A, 0x10F0: 0x02101FD8, 0x10F4: 0x02000850, 0x10F8: 0x02001050,
    0x10FC: 0x01B40FDA, 0x1100: 0x000C0362, 0x1104: 0x00008000, 0x1120: 0x068C0FDB,
    0x1124: 0x00900FD8, 0x1128: 0x80000390, 0x112C: 0x00002000, 0x1130: 0x80000812,
    0x1134: 0x00002000, 0x1138: 0x020003A8, 0x113C: 0x0188A42A, 0x1140: 0x0180006A,
    0x1144: 0x02101FD8, 0x1148: 0x02000850, 0x114C: 0x01B40FDA, 0x1150: 0x000C0362,
    0x1154: 0x00008000, 0x1160: 0x000C0362, 0x1164: 0x02108078, 0x1168: 0x00006000,
}


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x180)
    for address, word in WORDS.items():
        struct.pack_into(endian + "I", image, address - 0x1000, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
