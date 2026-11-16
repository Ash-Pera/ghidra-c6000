#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build jumps to a function whose link is a loop head on some path. Usage: IMAGE [be].

Load at 0x1000 with auto-analysis; C6000LinkJumpTest.java prepare declares the
functions, as ELF symbols would. Words are TI cl6x 8.3.15 output (-mv6740
--no_compress, linked at 0x1000), listed by dis6x. A displacement B to another
function's entry is a call when B3 holds a link this function built: the callee
returns to it (SPRUFE8B 3.5, 4.2.6 B). Where B3 may also be the caller's link the
jump is a loop call on one path and a tail call on the other.

  1000 h        B B3 ; ADD A4,A4,A4 ; NOP 4: 2v
  1020 g        B B3 ; ADD A4,3,A4 ; NOP 4: v + 3
  1040 ljloop   [!A2] B ll_top ; ... B3 = ll_top ; B h ; ll_top: SUB A2,1,A2 ;
                [A2] B g ; [!A2] MV B6,B3 ; NOP 4 ; B B3: n ? 2v + 3(n - 1) : g(v)
  1080 ljonly   B3 = lo_top ; lo_top: SUB A2,1,A2 ; [A2] B g ; [!A2] MV B6,B3 ; NOP 4 ;
                B B3: v + 3(n - 1) for n >= 1
  Known-bads, the jump keeps its transfer and its last slot carries nothing:
  10c0 ljwrite  the window builds the link past it: an ordinary call
  1100 ljbusy   the window holds another transfer
  1140 ljpred   the window rewrites the jump's predicate (upstream #66)
  1180 ljclob   the loop rewrites B3 between the link and the jump
"""

from pathlib import Path
import struct
import sys

WORDS = [
    0x000C0362, 0x02108078, 0x00006000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x000C0362, 0x02106058, 0x00006000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x030C0FDB, 0x01101FD8, 0xB0000410, 0x00008000, 0x0188302A, 0x0180006A, 0x0FFFF810, 0x00008000,
    0x010BE058, 0xAFFFF810, 0xB1980FDA, 0x00006000, 0x000C0362, 0x00008000, 0x00000000, 0x00000000,
    0x030C0FDB, 0x01101FD8, 0x0188482A, 0x0180006A, 0x010BE058, 0xAFFFF410, 0xB1980FDA, 0x00006000,
    0x000C0362, 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x030C0FDB, 0x01101FD8, 0x0188682A, 0x0180006A, 0x010BE058, 0xAFFFEC10, 0xA188742A, 0xA180006A,
    0xB1980FDA, 0x00004000, 0x00180362, 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x030C0FDB, 0x01101FD8, 0x0188882A, 0x0180006A, 0x010BE058, 0xAFFFE410, 0xB0180362, 0x00006000,
    0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x030C0FDB, 0x01101FD8, 0x0188A82A, 0x0180006A, 0xAFFFDC10, 0xA10BE058, 0x00006000, 0x00180362,
    0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x030C0FDB, 0x01101FD8, 0x0188C82A, 0x0180006A, 0x010BE058, 0x01980FDA, 0xAFFFD410, 0x00008000,
    0x000C0362, 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000
]


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x200)
    for index, word in enumerate(WORDS):
        struct.pack_into(endian + "I", image, 4 * index, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
