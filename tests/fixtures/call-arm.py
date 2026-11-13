#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build a jump with a call issued in its window on the opposite predicate. Usage: IMAGE [be].

Load at 0x1000 with auto-analysis; C6000CallArmTest.java prepare declares the
functions, as ELF symbols would. Words are TI cl6x 8.3.15 output (-mv6740
--no_compress, linked at 0x1000), listed by dis6x. Exactly one of [A1] B local
and [!A1] B callee transfers; the jump's window holds the call, whose window
outlasts the jump's by one cycle (SPRUFE8B 3.5, 4.2.6 B):

  1000 armcall   MV B3,B13 ; MV A4,A1 ; MVK/MVKH ret1,B3 ; NOP ;
                 [A1] B local1 || [A1] MVK 5,A5 ; [!A1] B callee ; [A1] ADD 1,A5,A7 ;
                 NOP 2 ; [A1] ADD 2,A7,A7 ; NOP ; ret1: MV B13,B3 ; B B3 ; NOP 5 ;
                 local1: MV A7,A4 ; B B13 ; NOP 5. Returns 8 when p, else callee(0)
  Known-bads, the call keeps its own window:
  1060 armsame   the call is under [A1], the jump's own predicate
  10c0 armwrite  the jump's packet writes A1 (MV A6,A1) before the call reads it
  1120 armentry  a [B0] jump enters the call's last slot
  1180 callee    B B3 ; ADD A4,A4,A4 ; NOP 4
"""

from pathlib import Path
import struct
import sys

WORDS = [
    0x068C0FDA, 0x00900FD8, 0x0188182A, 0x0180006A, 0x00000000, 0x80000791, 0x8294A358, 0x90003010,
    0x83942058, 0x00002000, 0x839C4058, 0x00000000, 0x01B40FDA, 0x000C0362, 0x00008000, 0x021C0FD8,
    0x00340362, 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x068C0FDA, 0x00900FD8, 0x0188482A, 0x0180006A, 0x00000000, 0x80000791, 0x8294A358, 0x80002410,
    0x83942058, 0x00002000, 0x839C4058, 0x00000000, 0x01B40FDA, 0x000C0362, 0x00008000, 0x021C0FD8,
    0x00340362, 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x068C0FDA, 0x00900FD8, 0x0188782A, 0x0180006A, 0x00000000, 0x80000791, 0x00980FD8, 0x90001810,
    0x83942058, 0x00002000, 0x839C4058, 0x00000000, 0x01B40FDA, 0x000C0362, 0x00008000, 0x021C0FD8,
    0x00340362, 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x068C0FDA, 0x00900FD8, 0x0188AA2A, 0x0180006A, 0x20000612, 0x00008000, 0x80000811, 0x8294A358,
    0x90000810, 0x83942058, 0x00002000, 0x839C4058, 0x00000000, 0x01B40FDA, 0x000C0362, 0x00008000,
    0x021C0FD8, 0x00340362, 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x000C0362, 0x02108078, 0x00006000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
]


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x1a0)
    for index, word in enumerate(WORDS):
        struct.pack_into(endian + "I", image, 4 * index, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
