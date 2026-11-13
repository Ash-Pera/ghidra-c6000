#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build jumps issued in another jump's window that land where its target code runs to. Usage: IMAGE [be].

Load at 0x1000 with auto-analysis; C6000LandedJumpTest.java prepare declares
the functions, as ELF symbols would. Words are TI cl6x 8.3.15 output (-mv6740
--abi=eabi --no_compress), listed by dis6x. The outer jump lands after its five
delay cycles; the inner jump, issued in cycle k of that window, lands k cycles
later, so the outer target runs k cycles first (SPRUFE8B 3.5, 4.2.6 B, NOP):

  1000 landall    B t1 ; LDW *A4,A2 ; NOP 3 ; B t1end ; t1: ADD A2,1,A4 ; NOP 3 ;
                  ADD A4,2,A4 ; t1end: B B3 ; NOP 5. The inner jump lands where t1
                  runs to: *p + 3, the load in the outer window included
  1040 landpred   MV A4,A1 ; NOP ; [A1] B t2 ; LDW *B4,A2 ; NOP 3 ; [A1] B t2end ;
                  MVK 7,A4 ; B B3 ; NOP 5 ; t2: ADD A2,1,A4 ; NOP 2 ; ADD A4,2,A4 ;
                  NOP ; NOP ; t2end: ... Both under [A1]; t2 runs five cycles to the
                  second NOP, which the landing skips: a ? *p + 3 : 7
  1080 landuncond MV A4,A1 ; NOP ; B t3 ; LDW *B4,A2 ; NOP 3 ; [A1] B t3end ; t3: ...
                  The outer jump is unconditional: *p + 3
  Known-bads, the inner jump keeps its target:
  10c0 landshort  t4 runs six cycles; the inner jump skips its last ADD
  1100 landother  the inner jump is under [B0], the outer one under [A1]
  1140 landentered [A1] B jin enters the outer window at the inner jump, whose own
                  slots then run MVK 9,A4: a ? 9 : *p + 3
"""

from pathlib import Path
import struct
import sys

WORDS = {
    0x1000: 0x00000210, 0x1004: 0x01100264, 0x1008: 0x00004000, 0x100C: 0x00000390,
    0x1010: 0x02082058, 0x1014: 0x00004000, 0x1018: 0x02104058, 0x101C: 0x000C0362,
    0x1020: 0x00008000, 0x1040: 0x00900FD8, 0x1048: 0x80000490, 0x104C: 0x011002E4,
    0x1050: 0x00004000, 0x1054: 0x80000710, 0x1058: 0x020003A8, 0x105C: 0x000C0362,
    0x1060: 0x00008000, 0x1064: 0x02082058, 0x1068: 0x00002000, 0x106C: 0x02104058,
    0x1078: 0x000C0362, 0x107C: 0x00008000, 0x1080: 0x00900FD8, 0x1088: 0x00000310,
    0x108C: 0x011002E4, 0x1090: 0x00004000, 0x1094: 0x80000490, 0x1098: 0x02082058,
    0x109C: 0x00004000, 0x10A0: 0x02104058, 0x10A4: 0x000C0362, 0x10A8: 0x00008000,
    0x10C0: 0x00000210, 0x10C4: 0x01100264, 0x10C8: 0x00004000, 0x10CC: 0x00000410,
    0x10D0: 0x02082058, 0x10D4: 0x00004000, 0x10D8: 0x02104058, 0x10DC: 0x02108058,
    0x10E0: 0x000C0362, 0x10E4: 0x00008000, 0x1100: 0x00900FD9, 0x1104: 0x00100FDA,
    0x110C: 0x80000510, 0x1110: 0x01180264, 0x1114: 0x00004000, 0x1118: 0x20000690,
    0x111C: 0x020003A8, 0x1120: 0x000C0362, 0x1124: 0x00008000, 0x1128: 0x02082058,
    0x112C: 0x00004000, 0x1130: 0x02104058, 0x1134: 0x000C0362, 0x1138: 0x00008000,
    0x1140: 0x00900FD8, 0x1148: 0x80000710, 0x114C: 0x00008000, 0x1150: 0x00000590,
    0x1154: 0x00008000, 0x1158: 0x02082058, 0x115C: 0x00004000, 0x1160: 0x02104058,
    0x1164: 0x000C0362, 0x1168: 0x00008000, 0x116C: 0x0FFFFF10, 0x1170: 0x011002E4,
    0x1174: 0x00004000, 0x1178: 0x00000090, 0x117C: 0x020004A8, 0x1180: 0x00006000,
}


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x1a0)
    for address, word in WORDS.items():
        struct.pack_into(endian + "I", image, address - 0x1000, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
