#!/usr/bin/env python3
"""Generate B IRP / B NRP cases, plain and predicated. IMAGE CASES.tsv [be]."""
import struct
import sys
from pathlib import Path

IRP = 0x001800E2      # B.S2 IRP (SPRUFE8B Figure F-8)
NRP = 0x001C00E2      # B.S2 NRP
B0 = 1 << 29          # [B0]
NOT_B1 = 0x5 << 28    # [!B1]

# word, operand, registers before, expected after (pc: irp, nrp or next)
CASES = [
    (IRP, "IRP", {"CSR": 0x102, "TSR": 0x4}, {"pc": "irp", "CSR": 0x103, "TSR": 0x5}),
    (IRP, "IRP", {"CSR": 0x101, "TSR": 0x5}, {"pc": "irp", "CSR": 0x100, "TSR": 0x4}),
    (IRP | B0, "IRP", {"B0": 1, "CSR": 0x2, "TSR": 0x0}, {"pc": "irp", "CSR": 0x3, "TSR": 0x1}),
    (IRP | B0, "IRP", {"B0": 0, "CSR": 0x2, "TSR": 0x0}, {"pc": "next", "CSR": 0x2, "TSR": 0x0}),
    (NRP, "NRP", {"IER": 0x1, "TSR": 0x5}, {"pc": "nrp", "IER": 0x3, "TSR": 0x5}),
    (NRP | NOT_B1, "NRP", {"B1": 0, "IER": 0x1}, {"pc": "nrp", "IER": 0x3}),
    (NRP | NOT_B1, "NRP", {"B1": 1, "IER": 0x1}, {"pc": "next", "IER": 0x1}),
]


def pairs(regs):
    return ",".join(f"{k}={v:x}" if isinstance(v, int) else f"{k}={v}"
                    for k, v in regs.items()) or "-"


def main():
    image, manifest = map(Path, sys.argv[1:3])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as out, manifest.open("w") as rows:
        for index, (word, operand, before, after) in enumerate(CASES):
            out.write(struct.pack(endian + "I", word))
            out.write(bytes(28))
            rows.write(f"{index}\t{operand}\t{pairs(before)}\t{pairs(after)}\n")


if __name__ == "__main__":
    main()
