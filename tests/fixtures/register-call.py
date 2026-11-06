#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build register-target B calls whose delay slots set B3 and arguments. Usage: IMAGE [be].

Load at 0x1000 with entry 0x1000 and auto-analysis; C6000RegisterCallTest.java
prepare declares the ten functions, as ELF symbols would. Words are TI cl6x
8.3.15 output (-mv6740 --no_compress), listed by dis6x (SPRUFE8B 4.2.6, B, ADDKPC):

  1000 rcall   STW B3 ; B.S2X A4 ; MVK/MVKH 0x101c,B3 ; ADD 1,B4,A4 ; MVK 7,B4 ; NOP
               fp(a + 1, 7) + 3: call, returns to 0x101c
       101c    LDW *++B15[2],B3 ; ADD 3,A4,A4 ; NOP 4 ; B B3 ; NOP 5
  1040 rknown  STW B3 ; MVK/MVKH sink,B5 ; B.S2 B5 ; MVK 5,A4 ; ADDKPC 0x1058,B3,3
               sink(5): call, returns to 0x1058 ; LDW B3 ; NOP 4 ; B B3 ; NOP 5
  1080 rtail   MVK/MVKH sink,B5 ; B.S2 B5 ; MVK 9,A4 ; NOP 4    B3 untouched: not a returning call
  10a0 rpred   STW B3 ; MV A4,A1 ; MVK/MVKH sink,B5 ; [A1] B.S2 B5 ; MVK 5,A4 ;
               MVK/MVKH 0x10c4,B3 ; NOP 2     call if A1, both paths continue at 0x10c4
       10c4    LDW *++B15[2],B3 ; NOP 4 ; B B3 ; NOP 5
  10e0 sink    ADD 1,A4,A4 ; B B3 ; NOP 5
  1100 rtwo    STW B3 ; MVK/MVKH sink,B5 ; B.S2 B5 ; MVK 5,A4 ; ADDKPC 0x1118,B3,3 ;
               MVK/MVKH sink2,B5 ; B.S2 B5 ; MVK 6,A4 ; ADDKPC 0x112c,B3,3 ; LDW B3 ; NOP 4 ; B B3 ; NOP 5
               two register calls to different constants
  1140 rcopy   MV B3,A0 ; MVK/MVKH sink,B5 ; B.S2 B5 ; ADDKPC 0x1154,B3,4 ; B.S2X A0 ; NOP 5
               returns through the entry copy of B3 in A0 after the call
  1160 rjump   LDW *A4,A1 ; NOP 4 ; B.S2X A1 ; NOP 5    a computed jump, B3 untouched
  1180 sink2   ADD 2,A4,A4 ; B B3 ; NOP 5
  11a0 rloop   MV B3,B13 ; B.S2X A4 ; MVK/MVKH 0x11b8,B3 ; NOP 3 ; NOP ; MV B13,B3 ; B B3 ; NOP 5
               a call whose fresh link is no sequential return point (a software-pipelined call loop shape)
  11e0 rcopy2  NOP ; MV B3,A0 ; MVK/MVKH sink,B5 ; B.S2 B5 ; ADDKPC 0x11f8,B3,4 ; B.S2X A0 ; NOP 5
               rcopy with the copy after the entry packet
"""

from pathlib import Path
import struct
import sys

WORDS = {
    0x1000: 0x01BC54F6, 0x1004: 0x00101362, 0x1008: 0x01880E2A, 0x100C: 0x0180006A,
    0x1010: 0x02103058, 0x1014: 0x020003AA, 0x101C: 0x01BC52E6, 0x1020: 0x02106058,
    0x1024: 0x00006000, 0x1028: 0x000C0362, 0x102C: 0x00008000, 0x1040: 0x01BC54F6,
    0x1044: 0x0288702A, 0x1048: 0x0280006A, 0x104C: 0x00140362, 0x1050: 0x020002A8,
    0x1054: 0x01866162, 0x1058: 0x01BC52E6, 0x105C: 0x00006000, 0x1060: 0x000C0362,
    0x1064: 0x00008000, 0x1080: 0x0288702A, 0x1084: 0x0280006A, 0x1088: 0x00140362,
    0x108C: 0x020004A8, 0x1090: 0x00006000, 0x10A0: 0x01BC54F6, 0x10A4: 0x00900FD8,
    0x10A8: 0x0288702A, 0x10AC: 0x0280006A, 0x10B0: 0x80140362, 0x10B4: 0x020002A8,
    0x10B8: 0x0188622A, 0x10BC: 0x0180006A, 0x10C0: 0x00002000, 0x10C4: 0x01BC52E6,
    0x10C8: 0x00006000, 0x10CC: 0x000C0362, 0x10D0: 0x00008000, 0x10E0: 0x02102058,
    0x10E4: 0x000C0362, 0x10E8: 0x00008000, 0x1100: 0x01BC54F6, 0x1104: 0x0288702A,
    0x1108: 0x0280006A, 0x110C: 0x00140362, 0x1110: 0x020002A8, 0x1114: 0x01866162,
    0x1118: 0x0288C02A, 0x111C: 0x0280006A, 0x1120: 0x00140362, 0x1124: 0x02000328,
    0x1128: 0x01836162, 0x112C: 0x01BC52E6, 0x1130: 0x00006000, 0x1134: 0x000C0362,
    0x1138: 0x00008000, 0x1140: 0x000C1FD8, 0x1144: 0x0288702A, 0x1148: 0x0280006A,
    0x114C: 0x00140362, 0x1150: 0x01858162, 0x1154: 0x00001362, 0x1158: 0x00008000,
    0x1160: 0x00900264, 0x1164: 0x00006000, 0x1168: 0x00041362, 0x116C: 0x00008000,
    0x1180: 0x02104058, 0x1184: 0x000C0362, 0x1188: 0x00008000, 0x11A0: 0x068C0FDA,
    0x11A4: 0x00101362, 0x11A8: 0x0188DC2A, 0x11AC: 0x0180006A, 0x11B0: 0x00004000,
    0x11B4: 0x00000000, 0x11B8: 0x01B406A2, 0x11BC: 0x000C0362, 0x11C0: 0x00008000,
    0x11E0: 0x00000000, 0x11E4: 0x000C1FD8, 0x11E8: 0x0288702A, 0x11EC: 0x0280006A,
    0x11F0: 0x00140362, 0x11F4: 0x01868162, 0x11F8: 0x00001362, 0x11FC: 0x00008000,
}


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x200)
    for address, word in WORDS.items():
        struct.pack_into(endian + "I", image, address - 0x1000, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
