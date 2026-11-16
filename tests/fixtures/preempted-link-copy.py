#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build a jump preempted by a return through an entry copy of B3. Usage: IMAGE [be].

Load at 0x1000 with auto-analysis; C6000PreemptedLinkCopyTest.java prepare declares
the functions, as ELF symbols would. Words are TI cl6x 8.3.15 output (-mv6740
--no_compress, linked at 0x1000) of self-written source, listed by dis6x. As
preempted-jump.py padret, with the returns through A0, the entry's copy of B3
(link-copy-return.py; SPRUFE8B 3.5, 4.2.6 B):

  1000 copyret   MV B3,A0 ; MV A4,A1 ; [A1] B pad1 ; MVK 0x100,A4 ; [A1] B A0 ||
                 ADDK 0x11,A4 ; NOP ; [!A1] MVK 0x200,A4 ; NOP ; ADDK 0x22,A4 ; B A0 ;
                 ADDK 0x111,A4 ; NOP 2 ; pad1: NOP 2. The return issues in c2 under the
                 jump's predicate and the jump lands on the fall-through return's last two
                 slots, which only idle until it lands: a ? 0x111 : 0x333
  Known-bad, the jump keeps its target:
  1040 copyother A0 copies B4, so B A0 is no return
"""

from pathlib import Path
import struct
import sys

WORDS = [
    0x000C1FD8, 0x00900FD8, 0x80000690, 0x02008028, 0x80001363, 0x020008D0, 0x00000000, 0x92010028,
    0x00000000, 0x02001150, 0x00001362, 0x020088D0, 0x00002000, 0x00002000, 0x00000000, 0x00000000,
    0x00101FD8, 0x00900FD8, 0x80000690, 0x02008028, 0x80001363, 0x020008D0, 0x00000000, 0x92010028,
    0x00000000, 0x02001150, 0x000C0362, 0x020088D0, 0x00002000, 0x00002000, 0x00000000, 0x00000000,
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
