#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build a register call paired with a complementary jump in one packet. Usage: IMAGE [be].

Load at 0x1000 with auto-analysis; C6000PairCallTest.java prepare declares the
functions, as ELF symbols would. Words are TI cl6x 8.3.15 output (-mv6740
--no_compress, linked at 0x1000) of self-written source, listed by dis6x. Exactly one
of [B0] B A0 (a call, link ret1) and [!B0] B other1 transfers, after the same
window (SPRUFE8B 3.5, 4.2.6 B):

  1000 paircall  MV B3,B13 || MV A4,B0 ; MVKL/MVKH callee,A0 ; NOP ;
                 [B0] B A0 || [!B0] B other1 || [B0] MVK 5,A4 ; [B0] MVKL/MVKH ret1,B3 ;
                 MVK 9,B4 ; [!B0] MVK 7,A4 ; NOP ; ret1: ADD 1,A4,A4 ;
                 other1: MV B13,B3 ; B B3 ; NOP 5. b ? callee(5, 9) + 1 : 7
  Known-bad, no pair:
  1060 pairentry as paircall, with an [A1] jump into the window's fourth slot
  10c0 callee    B B3 ; ADD A4,B4,A4 ; NOP 4
"""

from pathlib import Path
import struct
import sys

WORDS = [
    0x068C0FDB, 0x001016A2, 0x00086028, 0x00000068, 0x00000000, 0x20001363, 0x30000711, 0x2214A358,
    0x21881A2A, 0x2180006A, 0x020004AA, 0x321CA358, 0x00000000, 0x02102058, 0x01B40FDA, 0x000C0362,
    0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x068C0FDB, 0x001016A3, 0x009016A0, 0x00086028, 0x00000068, 0x80000610, 0x20001363, 0x30000791,
    0x2214A358, 0x21884C2A, 0x2180006A, 0x020004AA, 0x321CA358, 0x00000000, 0x02102058, 0x01B40FDA,
    0x000C0362, 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x000C0362, 0x02109078, 0x00006000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
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
