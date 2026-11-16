#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build a one-packet pipelined loop for assumed-drained schedules. Usage: IMAGE [be].

Load at 0x1000 with auto-analysis; C6000AssumedScheduleTest.java prepare declares the
functions. Words are TI cl6x 8.3.15 output of assumed-schedule.s (-mv6740 --no_compress,
linked at 0x1000), listed by dis6x:

  1000 pipe     int pipe(const int *s, int n), n >= 5: the sum of n words. Five prolog
                packets issue [B0] B loop each cycle; loop (1048) issues it again with
                [!A0] ADD A3,A4,A4 || LDW *A5++,A3, so up to five branches and four
                loads are in flight across the back edge (SPRUFE8B 3.5, 4.2.6)
  1080 plain    B B3 ; MVK 7,A4 ; entered: MVK 9,A4 ; NOP 3: returns 9
  1088 entered  known-bad: issued in plain's return window
  10a0 branchy  known-bad: B B3 || MVK 3,A4 ; NOP 5: a branch in the entry packet
  10c0 proved   MVK 5,A4 ; B B3 ; NOP 5: the test records its own review first
  10e0 ldread   LDW *A4,A3 ; NOP 2 ; ADD A3,A3,A4 ; B B3 ; NOP 5: reads the load 3 cycles early
  1100 tail     B B3 ; NOP 5, then follows (1108) MVK 4,A4 ; B B3 ; NOP 5: follows issues six
                cycles after tail's return, past its window, so it is scheduled
"""

from pathlib import Path
import struct
import sys

WORDS = [
    0x02900FD9, 0x02000029, 0x0013605A, 0x20000913, 0x2003E05A, 0x01943665, 0x20000913, 0x2003E05A,
    0x01943665, 0x20000513, 0x2003E05A, 0x01943665, 0x20000513, 0x2003E05A, 0x000000A9, 0x01943665,
    0x20000113, 0x2003E05A, 0xC003E1A1, 0xD2106079, 0x20000113, 0x2003E05B, 0x01943664, 0x02106078,
    0x02106078, 0x02106078, 0x02106078, 0x02106078, 0x000C0362, 0x00008000, 0x00000000, 0x00000000,
    0x000C0362, 0x020003A8, 0x020004A8, 0x00004000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x000C0363, 0x020001A8, 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x020002A8, 0x000C0362, 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x01900264, 0x00002000, 0x020C6078, 0x000C0362, 0x00008000, 0x00000000, 0x00000000, 0x00000000,
    0x000C0362, 0x00008000, 0x02000228, 0x000C0362, 0x00008000, 0x00000000, 0x00000000, 0x00000000,
]


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 3 else "<"
    image = bytearray(0x400)
    for index, word in enumerate(WORDS):
        struct.pack_into(endian + "I", image, 4 * index, word)
    Path(sys.argv[1]).write_bytes(image)


if __name__ == "__main__":
    main()
