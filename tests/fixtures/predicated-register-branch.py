#!/usr/bin/env python3
"""Build predicated register-branch functions. Usage: IMAGE CASES [be].

Load at 0x1000 with entry 0x1000 and auto-analysis. Each case is its own
function in its own fetch packet. Words are encoded from SPRUFE8B's B (register),
BNOP (register), SWE, SWENR, NOP and B.S2 B3 opcode diagrams:

  1000  [A1] B.S2 B4         ; NOP 5 ; B.S2 B3 ; NOP 5
  1020  [A1] BNOP.S2 B4,5    ; B.S2 B3 ; NOP 5
  1080  SWE                  ; B.S2 B3 ; NOP 5
  10a0  SWENR                ; B.S2 B3 ; NOP 5

None of the indirect targets is a recoverable jump table, so the decompiler
turns each indirect jump into a call followed by an artificial halt. A
predicated form that skips with a relative label to the end of its p-code is
then rejected with "Bad relative branch". C6000PredicatedBranchTest.java
checks that every case decodes as listed and decompiles to a conditional.
"""

from pathlib import Path
import struct
import sys


def nop(count):
    return (count - 1) << 13


A1 = 4 << 29                                 # creg A1, z=0
B_B3 = 0x362 | (3 << 18)
B_REG = 0x362                                # B.S2 src2
BNOP_REG = 0x362 | (1 << 23)                 # BNOP.S2 src2,src1
SWE = 0x10000000
SWENR = 0x10002000

# (address, expected listing text of the first word, words)
CASES = [
    (0x1000, "[A1]B.S2 B4", [A1 | B_REG | (4 << 18), nop(5), B_B3, nop(5)]),
    (0x1020, "[A1]BNOP.S2 B4,0x5", [A1 | BNOP_REG | (4 << 18) | (5 << 13), B_B3, nop(5)]),
    (0x1080, "SWE", [SWE, B_B3, nop(5)]),
    (0x10A0, "SWENR", [SWENR, B_B3, nop(5)]),
]
WORDS = {address + 4 * i: word for address, _, words in CASES
         for i, word in enumerate(words)}


def main():
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != "be"):
        raise SystemExit(__doc__)
    endian = ">" if len(sys.argv) == 4 else "<"
    image = bytearray(0x120)
    for address, word in WORDS.items():
        struct.pack_into(endian + "I", image, address - 0x1000, word)
    Path(sys.argv[1]).write_bytes(image)
    with Path(sys.argv[2]).open("w") as rows:
        for address, name, _ in CASES:
            rows.write(f"{address:x}\t{name}\n")


if __name__ == "__main__":
    main()
