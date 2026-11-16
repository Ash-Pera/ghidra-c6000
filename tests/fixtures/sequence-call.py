#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build a register call whose packet holds an in-sequence complementary jump. Usage: IMAGE [be].

Load at 0x1000 with auto-analysis; C6000SequenceCallTest.java prepare declares the
functions, as ELF symbols would. Words are TI cl6x 8.3.15 output (-mv6740
--no_compress, linked at 0x1000) of self-written source, listed by dis6x. The
[!B0] jump lands where sequential issue is, so it is inert (in-sequence-jump.py);
the [B0] call's window holds it as a packet companion (SPRUFE8B 3.5, 4.2.6 B):

  1000 seqcall   MV B3,B13 || MV A4,B0 ; MVKL/MVKH callee,A0 ; NOP ;
                 [B0] B A0 || [!B0] B ret1 || [B0] MVK 5,A4 ; [B0] MVKL/MVKH ret1,B3 ;
                 MVK 9,B4 ; NOP 2 ; ret1: MV B13,B3 ; B B3 ; NOP 5.
                 b ? callee(5, 9) : 0
  Known-bads: prepare sets c_inert on one more branch in the call's window, and the
  call gets no window over it:
  1040 seqreg    a [!B0] B B5 (register branch) in slot 2: c_arm cannot make it inert
  10a0 seqsame   the call is [!B0] B callee, the inert branch [!B0] B ret3: the c_arm
                 that makes it inert would make the call inert too
  10e0 seqmix    an inert [B0] B ret4 in slot 2 besides the [!B0] jump: two senses
  1120 sequnc    an inert unconditional B ret5 in slot 2: c_arm covers predicated B only
  1160 callee    B B3 ; ADD A4,B4,A4 ; NOP 4
"""

from pathlib import Path
import struct
import sys

WORDS = [
    0x068C0FDB, 0x001016A2, 0x0008B028, 0x00000068, 0x00000000, 0x20001363, 0x30000611, 0x2214A358,
    0x2188182A, 0x2180006A, 0x020004AA, 0x00002000, 0x01B40FDA, 0x000C0362, 0x00008000, 0x00000000,
    0x068C0FDB, 0x001016A2, 0x0008B028, 0x00000068, 0x02883C2A, 0x0280006A, 0x20001363, 0x30000711,
    0x2214A358, 0x21883C2A, 0x30140362, 0x2180006A, 0x020004AA, 0x00000000, 0x01B40FDA, 0x000C0362,
    0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x068C0FDB, 0x001016A2, 0x00000000, 0x30001811, 0x3214A358, 0x3188642A, 0x3180006A, 0x30000510,
    0x020004AA, 0x00000000, 0x01B40FDA, 0x000C0362, 0x00008000, 0x00000000, 0x00000000, 0x00000000,
    0x068C0FDB, 0x001016A2, 0x0008B028, 0x00000068, 0x00000000, 0x20001363, 0x30000691, 0x2214A358,
    0x21888A2A, 0x20000291, 0x2180006A, 0x020004AA, 0x00002000, 0x01B40FDA, 0x000C0362, 0x00008000,
    0x068C0FDB, 0x001016A2, 0x0008B028, 0x00000068, 0x00000000, 0x20001363, 0x30000691, 0x2214A358,
    0x2188AA2A, 0x00000291, 0x2180006A, 0x020004AA, 0x00002000, 0x01B40FDA, 0x000C0362, 0x00008000,
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
