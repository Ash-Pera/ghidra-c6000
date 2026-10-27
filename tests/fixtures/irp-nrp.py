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
    (IRP, "IRP", {}, {"pc": "irp"}),
    (IRP | B0, "IRP", {"B0": 1}, {"pc": "irp"}),
    (IRP | B0, "IRP", {"B0": 0}, {"pc": "next"}),
    (NRP, "NRP", {}, {"pc": "nrp"}),
    (NRP | NOT_B1, "NRP", {"B1": 0}, {"pc": "nrp"}),
    (NRP | NOT_B1, "NRP", {"B1": 1}, {"pc": "next"}),
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
