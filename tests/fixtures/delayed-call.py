#!/usr/bin/env python3
"""Build a B-with-B3 call image. Usage: IMAGE [be].

Load at 0x1000 with entry 0x1000 and auto-analysis. Words are encoded from
SPRUFE8B's MVK/MVKH, B, ADDKPC and NOP opcode diagrams:

  1000  MVK.S2  0x1100,B5        1018  B.S1    0x1100        (call)
  1004  MVKH.S2 0x0,B5           101c  ADDKPC.S2 0x1020,B3,4
  1008  B.S2    B5      (call)   1020  B.S2    B3            (return)
  100c  MVK.S2  0x1018,B3        1024  NOP     5
  1010  MVKH.S2 0x0,B3           ...
  1014  NOP     3                1100  B.S2 B3 ; NOP 5       (callee)

An if/else call pair, B3 set before the first arm:

  1040  MVK.S2  0x1054,B3        104c  [A1]B.S1  0x1100      (call)
  1044  MVKH.S2 0x0,B3           1050  NOP     4
  1048  [!A1]B.S1 0x1100 (call)  1054  B.S2 B3 ; NOP 5

A call-or-jump pair: call 0x1100 if A1, else jump to the local block 0x1080.
Only the far arm is a call:

  1060  MVK.S2  0x1074,B3        106c  [A1]B.S1  0x1100      (call)
  1064  MVKH.S2 0x0,B3           1070  NOP     4
  1068  [!A1]B.S1 0x1080 (jump)  1074  B.S2 B3 ; ...  1080  B.S2 B3

A conditional jump whose delay slots set B3 for the next call. B3 points past
the B at 10b8, so it is 10b8's return address and 10a0 stays a jump:

  10a0  [A1]B.S1  0x10e0 (jump)  10b0  MVKH.S2 0x0,B5
  10a4  MVK.S2  0x10c0,B3        10b4  NOP
  10a8  MVK.S2  0x1100,B5        10b8  B.S2    B5      (call)
  10ac  MVKH.S2 0x0,B3           10bc  NOP     5       10c0, 10e0  B.S2 B3

B3 set before a conditional jump for the call after it. The jump's fall-through
keeps B3, so 1150 is a call; 1148 stays a jump:

  1140  MVK.S2  0x1158,B3        1150  B.S1    0x11c0  (call)
  1144  MVKH.S2 0x0,B3           1154  NOP     5
  1148  [A1]B.S1  0x1180 (jump)  1158, 1180, 11c0  B.S2 B3
  114c  NOP     5

B3 set before a predicated B whose delay slots hold another predicated B. B3
is the outer B's return address, so the inner B at 120c stays a jump:

  1200  MVK.S2  0x1214,B3        120c  [!A1]B.S1 0x1240 (jump)
  1204  MVKH.S2 0x0,B3           1210  NOP     4
  1208  [B0]B.S1  0x1260         1214, 1240, 1260  B.S2 B3

B3 set before a conditional jump; a later unconditional B's window ends 4
bytes short of B3. A call returns exactly at its window end, so 1290 stays a
jump:

  1280  MVK.S2  0x12a0,B3        1294  NOP     4
  1284  MVKH.S2 0x0,B3           1298  NOP           (window ends 129c)
  1288  [A1]B.S1  0x12c0 (jump)  129c  NOP
  128c  NOP     5                12a0, 12c0, 12e0  B.S2 B3
  1290  B.S1    0x12e0 (jump)

C6000DelayedCallTest.java checks every B form becomes a call that falls
through into its delay slots and that 0x1100 becomes a function.
"""

from pathlib import Path
import struct
import sys


def mvk(cst, reg):
    return 0x2A | ((cst & 0xFFFF) << 7) | (reg << 23)


def mvkh(cst, reg):
    return 0x6A | ((cst & 0xFFFF) << 7) | (reg << 23)


def nop(count):
    return (count - 1) << 13


B_B3 = 0x362 | (3 << 18)

WORDS = {
    0x1000: mvk(0x1100, 5),
    0x1004: mvkh(0, 5),
    0x1008: 0x362 | (5 << 18),              # B.S2 B5
    0x100C: mvk(0x1018, 3),
    0x1010: mvkh(0, 3),
    0x1014: nop(3),
    0x1018: 0x10 | (0x40 << 7),             # B.S1 packet+0x100
    0x101C: 0x162 | (8 << 16) | (4 << 13) | (3 << 23),  # ADDKPC.S2 0x1020,B3,4
    0x1020: B_B3,
    0x1024: nop(5),
    0x1040: mvk(0x1054, 3),
    0x1044: mvkh(0, 3),
    0x1048: 0x90000010 | (0x30 << 7),       # [!A1] B.S1 packet+0xc0
    0x104C: 0x80000010 | (0x30 << 7),       # [A1] B.S1 packet+0xc0
    0x1050: nop(4),
    0x1054: B_B3,
    0x1058: nop(5),
    0x1060: mvk(0x1074, 3),
    0x1064: mvkh(0, 3),
    0x1068: 0x90000010 | (0x08 << 7),       # [!A1] B.S1 packet+0x20 (jump)
    0x106C: 0x80000010 | (0x28 << 7),       # [A1] B.S1 packet+0xa0 (call)
    0x1070: nop(4),
    0x1074: B_B3,
    0x1078: nop(5),
    0x1080: B_B3,
    0x1084: nop(5),
    0x10A0: 0x80000010 | (0x10 << 7),       # [A1] B.S1 packet+0x40 (jump)
    0x10A4: mvk(0x10C0, 3),
    0x10A8: mvk(0x1100, 5),
    0x10AC: mvkh(0, 3),
    0x10B0: mvkh(0, 5),
    0x10B4: nop(1),
    0x10B8: 0x362 | (5 << 18),              # B.S2 B5 (call)
    0x10BC: nop(5),
    0x10C0: B_B3,
    0x10C4: nop(5),
    0x10E0: B_B3,
    0x10E4: nop(5),
    0x1100: B_B3,
    0x1104: nop(5),
    0x1140: mvk(0x1158, 3),
    0x1144: mvkh(0, 3),
    0x1148: 0x80000010 | (0x10 << 7),       # [A1] B.S1 packet+0x40 (jump)
    0x114C: nop(5),
    0x1150: 0x10 | (0x20 << 7),             # B.S1 packet+0x80 (call)
    0x1154: nop(5),
    0x1158: B_B3,
    0x115C: nop(5),
    0x1180: B_B3,
    0x1184: nop(5),
    0x11C0: B_B3,
    0x11C4: nop(5),
    0x1200: mvk(0x1214, 3),
    0x1204: mvkh(0, 3),
    0x1208: 0x20000010 | (0x18 << 7),       # [B0] B.S1 packet+0x60
    0x120C: 0x90000010 | (0x10 << 7),       # [!A1] B.S1 packet+0x40 (jump)
    0x1210: nop(4),
    0x1214: B_B3,
    0x1218: nop(5),
    0x1240: B_B3,
    0x1244: nop(5),
    0x1260: B_B3,
    0x1264: nop(5),
    0x1280: mvk(0x12A0, 3),
    0x1284: mvkh(0, 3),
    0x1288: 0x80000010 | (0x10 << 7),       # [A1] B.S1 packet+0x40 (jump)
    0x128C: nop(5),
    0x1290: 0x10 | (0x18 << 7),             # B.S1 packet+0x60 (jump)
    0x1294: nop(4),
    0x1298: nop(1),
    0x129C: nop(1),
    0x12A0: B_B3,
    0x12A4: nop(5),
    0x12C0: B_B3,
    0x12C4: nop(5),
    0x12E0: B_B3,
    0x12E4: nop(5),
}


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x300)
    for address, word in WORDS.items():
        struct.pack_into(endian + "I", image, address - 0x1000, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
