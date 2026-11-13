#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build displacement jumps that land where sequential issue already is, or with their complement. Usage: IMAGE [be].

Load at 0x1000 with auto-analysis; C6000InSequenceJumpTest.java prepare declares the
functions, as ELF symbols would. Words are TI cl6x 8.3.15 output (-mv6740 --no_compress,
linked at 0x1000), listed by dis6x. A B whose target is the execute packet that issues
in its landing cycle anyway, with no other branch pending, transfers nowhere: its delay
slots and the code past them run in sequence (SPRUFE8B 3.5, 4.2.6 B):

  1000 seqone    B L1 || MVK 1,A4 ; ADDK 2/4/8/16/32,A4 ; L1: B B3 ; ADDK 64,A4 ; NOP 4: 127
  1040 seqnest   B N1 in c0, B N2 in c2, B N3 in c3, each landing in sequence, between
                 ADDKs 1..512: 1023
  1080 seqpair   [B0] B A0 (out1) || [!B0] B P1 in one packet; P1 is in sequence, its
                 complement is a real jump: b ? 0x100 : 127
  10e0 seqpredok [B0] B out2 in c2, [!B0] B R1 in c4 with B0 unchanged: b ? 0x101 : 255
  11e0 seqfork   [A1] B B3 || [!A1] B F1: one packet, one window; the return owns it and
                 its not-taken fall-through is F1: a ? 63 : 127
  1220 seqtail   as seqone, with a function declared at T1 (a seeded entry only this jump
                 reaches; prepare marks the jump a tail call, as analysis leaves one): 127
  Known-bads, the jump keeps its transfer:
  1120 seqearly  the target is one packet past the landing: 127
  1160 seqpend   B Q1 issued in the window of a real [A1] B Q9, which lands first when
                 taken: a ? 2143 : 1119
  11a0 seqpredw  as seqpredok, with MV A5,B0 between the two branches
"""

from pathlib import Path
import struct
import sys

WORDS = [
    0x00000393, 0x020000A8, 0x02000150, 0x02000250, 0x02000450, 0x02000850, 0x02001050, 0x000C0362,
    0x02002050, 0x00006000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000493, 0x020000A8, 0x02000150, 0x00000593, 0x02000250, 0x00000613, 0x02000450, 0x02000850,
    0x02001050, 0x02002050, 0x02004050, 0x02008050, 0x000C0362, 0x02010050, 0x00006000, 0x00000000,
    0x00101FDB, 0x00085C28, 0x00000068, 0x020000A8, 0x20001363, 0x30000590, 0x32000150, 0x32000250,
    0x32000450, 0x32000850, 0x32001050, 0x000C0362, 0x02002050, 0x00006000, 0x000C0362, 0x02008028,
    0x00006000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00101FDA, 0x020000A8, 0x20000692, 0x32000150, 0x30000510, 0x32000250, 0x32000450, 0x32000850,
    0x02001050, 0x02004050, 0x000C0362, 0x02002050, 0x00006000, 0x000C0362, 0x02008050, 0x00006000,
    0x00000413, 0x020000A8, 0x02000150, 0x02000250, 0x02000450, 0x02000850, 0x02001050, 0x02020050,
    0x000C0362, 0x02002050, 0x00006000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00900FD8, 0x80000613, 0x020000A8, 0x00000490, 0x02000150, 0x02000250, 0x02000450, 0x02000850,
    0x02020050, 0x000C0362, 0x02002050, 0x00006000, 0x02040050, 0x00008000, 0x00000000, 0x00000000,
    0x00101FDA, 0x020000A8, 0x20000692, 0x00141FDA, 0x30000510, 0x02000250, 0x02000450, 0x02000850,
    0x02001050, 0x02004050, 0x000C0362, 0x02002050, 0x00006000, 0x000C0362, 0x02008050, 0x00006000,
    0x00900FD8, 0x020000A8, 0x800C0363, 0x90000510, 0x02000150, 0x02000250, 0x02000450, 0x02000850,
    0x02001050, 0x02020050, 0x000C0362, 0x02002050, 0x00006000, 0x00000000, 0x00000000, 0x00000000,
    0x00000393, 0x020000A8, 0x02000150, 0x02000250, 0x02000450, 0x02000850, 0x02001050, 0x000C0362,
    0x02002050, 0x00006000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
]


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x260)
    for index, word in enumerate(WORDS):
        struct.pack_into(endian + "I", image, 4 * index, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
