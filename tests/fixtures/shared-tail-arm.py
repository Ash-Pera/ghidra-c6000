#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build a shared call tail whose jump also holds a call arm in its window. Usage: IMAGE [be].

Load at 0x1000 with auto-analysis; C6000SharedTailArmTest.java prepare declares the
functions, as ELF symbols would. Words are TI cl6x 8.3.15 output (-mv6740
--no_compress, linked at 0x1000) of self-written source, listed by dis6x. The loop's
[A1] jump enters the owning call's last cycle (shared-tail.py), and the jump's window
holds both a call to the tail's callee under [A1] and a call to callee2 under [!A1],
whose window outlasts the jump's (call-arm.py); the jump's slots set B4, an argument
of the carried call (SPRUFE8B 3.5, 4.2.6 B):

  1000 tailarm   MV B3,B13 || MV A4,A10 ; B callee ; MVK 1,A4 ; MVKL/MVKH ret1,B3 ;
                 MVK 7,B4 ; tail1: NOP ; ret1: SUB A10,1,A10 ; MV A10,A1 ;
                 [A1] B tail1 || [A1] MVKL ret1,B3 ; [A1] B callee || [!A1] MVKL exit1,B3 ;
                 [!A1] B callee2 || [!A1] MVKH exit1,B3 ; [A1] MVK 7,B4 ; [A1] MVKH ret1,B3 ;
                 [A1] ADD 1,A4,A4 ; NOP 2 ;
                 exit1: MV B13,B3 ; B B3 ; NOP 5. x = callee(1, 7), then
                 x = callee(x + 1, 7) while --n, then callee2(x)
  Known-bad, no carried call arm:
  1060 armother  as tailarm, the loop's [A1] call goes to callee3: no shared tail, so
                 two calls transfer in the jump's window
  10c0 callee    B B3 ; ADD A4,B4,A4 ; NOP 4
  10e0 callee2   B B3 ; ADD 3,A4,A4 ; NOP 4
  1100 callee3   B B3 ; ADD 5,A4,A4 ; NOP 4
"""

from pathlib import Path
import struct
import sys

WORDS = [
    0x068C0FDB, 0x05100FD8, 0x00001810, 0x020000A8, 0x0188102A, 0x0180006A, 0x020003AA, 0x00000000,
    0x052BE058, 0x00A80FD8, 0x8FFFFF91, 0x8188102A, 0x80001411, 0x9188282A, 0x90001811, 0x9180006A,
    0x820003AA, 0x8180006A, 0x82102058, 0x00002000, 0x01B40FDA, 0x000C0362, 0x00008000, 0x00000000,
    0x068C0FDB, 0x05100FD8, 0x00000C10, 0x020000A8, 0x0188402A, 0x0180006A, 0x020003AA, 0x00000000,
    0x052BE058, 0x00A80FD8, 0x8FFFFF91, 0x8188402A, 0x80001011, 0x9188582A, 0x90000C11, 0x9180006A,
    0x820003AA, 0x8180006A, 0x82102058, 0x00002000, 0x01B40FDA, 0x000C0362, 0x00008000, 0x00000000,
    0x000C0362, 0x02109078, 0x00006000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x000C0362, 0x02106058, 0x00006000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x000C0362, 0x0210A058, 0x00006000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
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
