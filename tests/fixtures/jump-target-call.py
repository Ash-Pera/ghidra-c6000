#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build jumps whose target runs until a call issued in their window lands. Usage: IMAGE [be].

Load at 0x1000 with auto-analysis; C6000JumpTargetCallTest.java prepare declares the
functions, as ELF symbols would. Words are TI cl6x 8.3.15 output (-mv6740
--no_compress, linked at 0x1000), listed by dis6x. The call is taken exactly when
the jump is; the jump's target runs transfer-free code until the call lands, and
the call's link is the address just past it (SPRUFE8B 3.5, 4.2.6 B). Ghidra parses a
jump's slots in the jump's context, where a displacement B under the jump's predicate
stays a branch: with a direct call the jump keeps no native window, and its last slot
takes it.

  1000 h        B B3 ; ADD A4,A4,A4 ; NOP 4
  1020 g        B B3 ; ADD A4,3,A4 ; NOP 4
  10a0 tcreg    [!A1] B rn_nop ; MVKL/MVKH rn_ret,B3 ; MVKL/MVKH h,A3 ; [!A1] B A3 ;
                ADD 7,A4 ... rn_nop: NOP 5 ; rn_ret: ADD 1,A4: c ? v + 7 : h(v) + 1
  1100 tcarm    [!A1] B an_nop, an [A1] B g call arm in its window and [!A1] B A3 in its
                last slot: c ? g(v) + 16 : h(v) + 1
  1180 tcbusy   [A1] B bu_tgt ; MVKL/MVKH h,A3 ; [A1] B A3 ; NOP 2 ; ... bu_tgt: MVKL/MVKH
                bu_ret,B3 ; ADD 2,A4 ; bu_ret: ADD 1,A4: c ? h(v + 2) + 1 : v + 7
  1040 tcdir    tcreg with the displacement call [!A1] B h
  13c0 tcearly  tcbusy with the displacement call [A1] B h
  1420 tcboth   [A1] B bo_tgt ; [!A1] B g (a call arm) ; [A1] B h ; [!A1] MVKL/MVKH
                bo_gret,B3 ; NOP ; NOP ... bo_tgt: MVKL bo_ret,B3 || ADD 2,A4 ; MVKH:
                c ? h(v + 2) + 1 : g(v) + 16
  Known-bads, the call keeps its transfer (register calls):
  11e0 tcindep  the call is under [B0], independent of the jump's [!A1]
  1240 tclink   the link is one packet past the target's NOPs
  12a0 tcfall   the target's NOPs are also reached in sequence
  12e0 tcuncond the call is unconditional, so taken on the jump's fall-through too,
                past a NOP 5 that idles as the target does
  1340 tcentry  as tcreg, with 13a0 tcenter jumping into its target's NOPs
"""

from pathlib import Path
import struct
import sys

WORDS = [
    0x000C0362, 0x02108078, 0x00006000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x000C0362, 0x02106058, 0x00006000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x01BC54F7, 0x00900FD8, 0x02101FD8, 0x90000690, 0x01883C2A, 0x0180006A, 0x00002000, 0x9FFFF810,
    0x0210E058, 0x01BC52E6, 0x00006000, 0x000C0362, 0x00008000, 0x00008000, 0x02102058, 0x01BC52E6,
    0x00006000, 0x000C0362, 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x01BC54F7, 0x00900FD8, 0x02101FD8, 0x90000710, 0x01886E2A, 0x0180006A, 0x01880028, 0x01800068,
    0x900C1362, 0x0210E058, 0x01BC52E6, 0x00006000, 0x000C0362, 0x00008000, 0x00008000, 0x02102058,
    0x01BC52E6, 0x00006000, 0x000C0362, 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x01BC54F7, 0x00900FD8, 0x02101FD8, 0x01880028, 0x01800068, 0x90000991, 0x9188A82A, 0x8FFFE411,
    0x81889C2A, 0x8180006A, 0x00000000, 0x9180006A, 0x900C1362, 0x00000000, 0x02000850, 0x01BC52E6,
    0x00006000, 0x000C0362, 0x00008000, 0x00008000, 0x02102058, 0x01BC52E6, 0x00006000, 0x000C0362,
    0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x01BC54F7, 0x00900FD8, 0x02101FD8, 0x80000690, 0x01880028, 0x01800068, 0x800C1362, 0x00002000,
    0x0210E058, 0x01BC52E6, 0x00006000, 0x000C0362, 0x00008000, 0x0188E02A, 0x0180006A, 0x02104058,
    0x02102058, 0x01BC52E6, 0x00006000, 0x000C0362, 0x00008000, 0x00000000, 0x00000000, 0x00000000,
    0x01BC54F7, 0x00900FD8, 0x02101FD9, 0x00100FDA, 0x90000790, 0x0189102A, 0x0180006A, 0x01880028,
    0x01800068, 0x200C1362, 0x0210E058, 0x01BC52E6, 0x00006000, 0x000C0362, 0x00008000, 0x00008000,
    0x02102058, 0x01BC52E6, 0x00006000, 0x000C0362, 0x00008000, 0x00000000, 0x00000000, 0x00000000,
    0x01BC54F7, 0x00900FD8, 0x02101FD8, 0x90000710, 0x0189402A, 0x0180006A, 0x01880028, 0x01800068,
    0x900C1362, 0x0210E058, 0x01BC52E6, 0x00006000, 0x000C0362, 0x00008000, 0x00008000, 0x02102058,
    0x01BC52E6, 0x00006000, 0x000C0362, 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x01BC54F7, 0x00900FD8, 0x02101FD8, 0x90000510, 0x0189662A, 0x0180006A, 0x01880028, 0x01800068,
    0x900C1362, 0x0210E058, 0x00008000, 0x02102058, 0x01BC52E6, 0x00006000, 0x000C0362, 0x00008000,
    0x01BC54F7, 0x00900FD8, 0x02101FD8, 0x90000790, 0x0189902A, 0x0180006A, 0x01880028, 0x01800068,
    0x000C1362, 0x00008000, 0x0210E058, 0x01BC52E6, 0x00006000, 0x000C0362, 0x00008000, 0x00008000,
    0x02102058, 0x01BC52E6, 0x00006000, 0x000C0362, 0x00008000, 0x00000000, 0x00000000, 0x00000000,
    0x01BC54F7, 0x00900FD8, 0x02101FD8, 0x90000710, 0x0189BE2A, 0x0180006A, 0x01880028, 0x01800068,
    0x900C1362, 0x0210E058, 0x01BC52E6, 0x00006000, 0x000C0362, 0x00008000, 0x00008000, 0x02102058,
    0x01BC52E6, 0x00006000, 0x000C0362, 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x0FFFFB10, 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x01BC54F7, 0x00900FD8, 0x02101FD8, 0x80000610, 0x00002000, 0x8FFF8810, 0x00002000, 0x0210E058,
    0x01BC52E6, 0x00006000, 0x000C0362, 0x00008000, 0x0189FE2A, 0x0180006A, 0x02104058, 0x02102058,
    0x01BC52E6, 0x00006000, 0x000C0362, 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x01BC54F7, 0x00900FD8, 0x02101FD8, 0x80000810, 0x9FFF8010, 0x8FFF7C10, 0x918A242A, 0x9180006A,
    0x00000000, 0x00000000, 0x02000851, 0x00000000, 0x01BC52E6, 0x00006000, 0x000C0362, 0x00008000,
    0x018A362B, 0x02104058, 0x0180006A, 0x02102058, 0x01BC52E6, 0x00006000, 0x000C0362, 0x00008000
]


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x480)
    for index, word in enumerate(WORDS):
        struct.pack_into(endian + "I", image, 4 * index, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
