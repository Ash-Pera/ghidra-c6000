#!/usr/bin/env python3
"""Generate stores through misaligned addresses (SPRUFE8B: STH/STW/STDW ignore the low address bits)."""
import struct
import sys
from pathlib import Path


# cl6x 8.3.15 -mv6740 words; base register, base value, data register(s), value, width, base after
CASES = [
    (0x01100274, "STW", "A4", 0x1302, "A2", 0xAABBCCDD, 4, 0x1302),        # STW.D1T1 A2,*+A4[0]
    (0x01100254, "STH", "A4", 0x1301, "A2", 0xBEEF, 2, 0x1301),            # STH.D1T1 A2,*+A4[0]
    (0x01100344, "STDW", "A4", 0x1314, "A3_A2", 0x1122334455667788, 8, 0x1314),  # STDW.D1T1 A3:A2,*+A4[0]
    (0x011022F6, "STW", "B4", 0x131B, "B2", 0x01020304, 4, 0x131B),        # STW.D2T2 B2,*+B4[1]
    (0x013C54F6, "STW", "B15", 0x1348, "B2", 0x0A0B0C0D, 4, 0x1340),       # STW.D2T2 B2,*B15--[2]; SP 8-byte aligned (SPRAB89 3.2)
    (0x01100234, "STB", "A4", 0x1303, "A2", 0x5A, 1, 0x1303),              # STB.D1T1 A2,*+A4[0]
]
OFFSET = {0x011022F6: 4}


def main():
    image, manifest = map(Path, sys.argv[1:3])
    byteorder = "big" if len(sys.argv) > 3 and sys.argv[3] == "be" else "little"
    endian = ">" if byteorder == "big" else "<"
    data = bytearray(0x500)
    for index, case in enumerate(CASES):
        struct.pack_into(endian + "I", data, index * 32, case[0])
    image.parent.mkdir(parents=True, exist_ok=True)
    image.write_bytes(data)
    with manifest.open("w") as out:
        for index, (_, mnemonic, base, address, target, value, width, after) in enumerate(CASES):
            effective = (address + OFFSET.get(CASES[index][0], 0)) & ~(width - 1)
            out.write("\t".join((str(index), mnemonic, base, f"{address:x}", target, f"{value:x}", str(width),
                                 f"{effective:x}", value.to_bytes(width, byteorder).hex(), f"{after:x}")) + "\n")


if __name__ == "__main__":
    main()
