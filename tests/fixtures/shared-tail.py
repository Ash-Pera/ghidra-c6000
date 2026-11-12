#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build call tails shared by a jump whose call lands after the tail. Usage: IMAGE [be].

Load at 0x1000 with auto-analysis; C6000SharedTailTest.java prepare declares the
functions, as ELF symbols would. Words are TI cl6x 8.3.15 output (-mv6740
--no_compress), listed by dis6x. A jump into the last cycles of a call's window,
with a call to the same function and link issued in the jump's own window, runs
those cycles and then that call (SPRUFE8B 3.5, 4.2.6 B):

  1000 tailidle  MV B3,B13 || MV A4,A10 ; B callee ; MVK 1,A4 ; MVKL/MVKH ret1,B3 ; NOP ;
                 tail1: NOP ; ret1: SUB A10,1,A10 ; MV A10,A1 ; [A1] B tail1 ;
                 [A1] B callee ; [A1] ADD 1,A4,A4 ; [A1] MVKL/MVKH ret1,B3 ; NOP ;
                 MV B13,B3 ; B B3 ; NOP 5. The loop's call lands after tail1's NOP:
                 x = callee(1), then callee(x + 1) while --n
  1060 tailbusy  as tailidle with tail2: MV A11,A4, the call's argument: x = callee(a),
                 then a += x, x = callee(a) while --n
  Known-bads, no carried call:
  10c0 tailpred  the first call is under [B0]: not taken, its tail runs with no call
  1120 tailother the loop calls callee2, not the tail's callee
  1180 tailentry a [B0] jump enters tail5 with no call pending
  11e0 callee    B B3 ; ADD A4,A4,A4 ; NOP 4
  1200 callee2   B B3 ; ADD 3,A4,A4 ; NOP 4
"""

from pathlib import Path
import struct
import sys

WORDS = [
    0x068C0FDB, 0x05100FD8, 0x00003C10, 0x020000A8, 0x0188102A, 0x0180006A, 0x00000000, 0x00000000,
    0x052BE058, 0x00A80FD8, 0x8FFFFF90, 0x80003812, 0x82102058, 0x8188102A, 0x8180006A, 0x00000000,
    0x01B40FDA, 0x000C0362, 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x068C0FDB, 0x05100FD9, 0x059806A0, 0x00003010, 0x0188402A, 0x0180006A, 0x00002000, 0x022C0FD8,
    0x052BE058, 0x00A80FD8, 0x8FFFFF90, 0x80002C12, 0x85AC8078, 0x8188402A, 0x8180006A, 0x00000000,
    0x01B40FDA, 0x000C0362, 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x068C0FDB, 0x05100FD9, 0x059806A1, 0x001008F2, 0x20002410, 0x0188722A, 0x0180006A, 0x00002000,
    0x022C0FD8, 0x052BE058, 0x00A80FD8, 0x80000010, 0x80002012, 0x85AC8078, 0x8188722A, 0x8180006A,
    0x00000000, 0x01B40FDA, 0x000C0362, 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x068C0FDB, 0x05100FD9, 0x059806A0, 0x00001810, 0x0188A02A, 0x0180006A, 0x00002000, 0x022C0FD8,
    0x052BE058, 0x00A80FD8, 0x8FFFFF90, 0x80001812, 0x85AC8078, 0x8188A02A, 0x8180006A, 0x00000000,
    0x01B40FDA, 0x000C0362, 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x068C0FDB, 0x05100FD9, 0x059806A1, 0x001008F2, 0x20000512, 0x00008000, 0x00000C10, 0x0188D62A,
    0x0180006A, 0x00002000, 0x022C0FD8, 0x052BE058, 0x00A80FD8, 0x80000110, 0x80000812, 0x85AC8078,
    0x8188D62A, 0x8180006A, 0x00000000, 0x01B40FDA, 0x000C0362, 0x00008000, 0x00000000, 0x00000000,
    0x000C0362, 0x02108078, 0x00006000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x000C0362, 0x02106058, 0x00006000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
]


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x240)
    for index, word in enumerate(WORDS):
        struct.pack_into(endian + "I", image, 4 * index, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
