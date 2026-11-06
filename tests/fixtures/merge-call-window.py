#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build a delayed call in a packet a flow repair disassembles outside any body.

Load at 0x1000. C6000MergeCallWindowTest.java declares only `handler` at 0x1000;
nothing reaches the packet at 0x1040, so auto-analysis never disassembles or owns
it (as the firmware's switch-merge calls, which Ghidra's switch recovery cannot
reach, are only disassembled later by a flow override). The test then decodes the
packet with no function over it and runs delay-window recovery, the single pass a
-noanalysis flow repair gets. Words are TI opcode-diagram encodings (SPRUFE8B 3.5,
4.2.6 B, LDW, ADDAW, ADD, NOP):

  1000 handler  B B3 ; NOP 5                         a self-contained return
  1040 packet   LDW *+B4[1],B5 || B callee ;         issue packet: a parallel load
                ADDAW B15,9,B4 ; NOP 3 ; ADD 0,B5,A4 three delay slots, the last
                                                     copying B5 into A4 (the call's
                                                     argument), then a return
  1080 callee   B B3 ; NOP 5

The call's five delay cycles span the three slots (1+3+1), so its proven window is
12 bytes ending at the ADD. If the window is not recovered, that ADD (A4 = B5) is
lifted after the call and the call reads a stale A4.
"""

from pathlib import Path
import struct
import sys

WORDS = {
    0x1000: 0x000C0362, 0x1004: 0x00008000,
    0x1040: 0x029022E7, 0x1044: 0x00000810, 0x1048: 0x023D3D42,
    0x104C: 0x00004000, 0x1050: 0x02141058, 0x1054: 0x000C0362, 0x1058: 0x00008000,
    0x1080: 0x000C0362, 0x1084: 0x00008000,
}


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x100)
    for address, word in WORDS.items():
        struct.pack_into(endian + "I", image, address - 0x1000, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
