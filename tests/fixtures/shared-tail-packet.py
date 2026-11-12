#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build shared call tails whose call, tail or issuing call's window holds a packet. Usage: IMAGE [be].

Load at 0x1000 with auto-analysis; C6000SharedTailPacketTest.java prepare declares the
functions. Words are TI cl6x 8.3.15 output (-mv6740 --no_compress) of self-written source,
listed by dis6x. The functions are shared-tail.py's tailidle/tailbusy with one packet
changed so that it is staged (a member reads a register an earlier member writes,
SPRUFE8B 3.5):

  1000 pktowner  MV B3,B13 || MV A4,A10 || MV A10,A12 || B callee ; MVK 1,A4 ;
                 MVKL/MVKH ret1,B3 ; NOP ; tail1: NOP ; ret1: SUB A10,1,A10 ; MV A10,A1 ;
                 [A1] B tail1 ; [A1] B callee ; [A1] ADD 1,A4,A4 ; [A1] MVKL/MVKH ret1,B3 ;
                 NOP ; MV B13,B3 ; B B3 ; NOP 5. The owning call's packet commits A10 at
                 the branch, which carryTails makes inert.
  1060 pkttail   MV B3,B13 || MV A4,A10 || MV A6,A11 ; B callee ; MVK 1,A4 ;
                 MVKL/MVKH ret2,B3 ; NOP ; tail2: MV A11,A4 || MV A4,A5 ; ret2: ... as
                 tailbusy. The tail's last instruction carries the call and ends a packet
                 that commits A4, the call's argument.
  10c0 pktslot   tailidle whose issuing call [A1] B callee || [A1] MVKL ret3,B3 has a packet
                 companion, then [A1] ADD 1,A4,A4 || [A1] MV A4,A11 (staged) in its window:
                 making the call inert must re-decode the companion and keep the staging.
  1120 callee    B B3 ; ADD A4,A4,A4 ; NOP 4
  1140 callee2   B B3 ; ADD 3,A4,A4 ; NOP 4
  1160 pktfw     as the firmware: [A1] B tail4 || [A1] ADD 1,A4,A4 ; [!A1] B callee2 ||
                 [!A1] MVKL exit4,B3 ; [A1] B callee || [A1] MVKL ret4,B3 ; ... with a
                 two-cycle tail (tail4: NOP 2). The opposite-predicate call to callee2 is
                 issued in the jump's window and holds the issuing call in its own window.
"""

from pathlib import Path
import struct
import sys

WORDS = [
    0x068C0FDB, 0x05100FD9, 0x062808F1, 0x00002410, 0x020000A8, 0x0188122A, 0x0180006A, 0x00000000,
    0x00000000, 0x052BE058, 0x00A80FD8, 0x80000010, 0x80002012, 0x82102058, 0x8188122A, 0x8180006A,
    0x00000000, 0x01B40FDA, 0x000C0362, 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x068C0FDB, 0x05100FD9, 0x059806A0, 0x00001810, 0x020000A8, 0x0188442A, 0x0180006A, 0x00000000,
    0x022C0FD9, 0x029006A0, 0x052BE058, 0x00A80FD8, 0x80000010, 0x80001412, 0x85AC8078, 0x8188442A,
    0x8180006A, 0x00000000, 0x01B40FDA, 0x000C0362, 0x00008000, 0x00000000, 0x00000000, 0x00000000,
    0x068C0FDB, 0x05100FD8, 0x00000C10, 0x020000A8, 0x0188702A, 0x0180006A, 0x00000000, 0x00000000,
    0x052BE058, 0x00A80FD8, 0x8FFFFF90, 0x80000811, 0x8188702A, 0x82102059, 0x859006A0, 0x8180006A,
    0x00000000, 0x00000000, 0x01B40FDA, 0x000C0362, 0x00008000, 0x00000000, 0x00000000, 0x00000000,
    0x000C0362, 0x02108078, 0x00006000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x000C0362, 0x02106058, 0x00006000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x068C0FDB, 0x05100FD8, 0x0FFFF810, 0x020000A8, 0x0188BE2A, 0x0180006A, 0x00002000, 0x052BE058,
    0x00A80FD8, 0x8FFFFF13, 0x82102058, 0x9FFFF811, 0x9188D42A, 0x8FFFF411, 0x8188BE2A, 0x8180006A,
    0x9180006A, 0x00002000, 0x01B40FDA, 0x000C0362, 0x00008000, 0x00000000, 0x00000000, 0x00000000,
]


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(4 * len(WORDS))
    for index, word in enumerate(WORDS):
        struct.pack_into(endian + "I", image, 4 * index, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
