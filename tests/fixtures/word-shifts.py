#!/usr/bin/env python3
"""Build 32-bit SHL/SHR/SHRU count-masking cases. Usage: IMAGE CASES [be]."""

from pathlib import Path
import struct
import sys


OPFIELDS = {
    "SHL": (0x33, 0x32),
    "SHR": (0x37, 0x36),
    "SHRU": (0x27, 0x26),
}
CASES = [
    (True, 0x80000001, 0),
    (True, 0x80000001, 1),
    (True, 0x80000001, 31),
    (True, 0x80000001, 32),
    (True, 0x80000001, 63),
    (True, 0x80000001, 64),
    (True, 0x80000001, 65),
    (True, 0x80000001, 0xffffffc1),
    (False, 0x80000001, 0),
    (False, 0x80000001, 31),
]


def result(mnemonic, source, count):
    count &= 63
    if mnemonic == "SHL":
        return (source << count) & 0xffffffff
    if mnemonic == "SHRU":
        return source >> count
    signed = source if source < 0x80000000 else source - 0x100000000
    return (signed >> count) & 0xffffffff


def main():
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != "be"):
        raise SystemExit(__doc__)
    image, manifest = Path(sys.argv[1]), Path(sys.argv[2])
    endian = ">" if len(sys.argv) == 4 else "<"
    with image.open("wb") as binary, manifest.open("w") as rows:
        for mnemonic, (reg_op, imm_op) in OPFIELDS.items():
            for register_count, source, count in CASES:
                # Each row occupies a separate 32-byte fetch packet.
                index = binary.tell() // 32
                side = 1 if index % 2 == 0 else 2
                cross = index % 3 == 0
                own, other = ("A", "B") if side == 1 else ("B", "A")
                op = reg_op if register_count else imm_op
                encoded_count = 1 if register_count else count & 31
                word = ((3 << 23) | (2 << 18) | (encoded_count << 13)
                        | (int(cross) << 12) | (op << 6) | 0x20 | ((side - 1) << 1))
                binary.write(struct.pack(endian + "I", word) + bytes(28))
                rows.write(f"{index}\t{mnemonic}.S{side}\t"
                           f"{other if cross else own}2\t"
                           f"{own + '1' if register_count else '-'}\t{own}3\t"
                           f"{source:08x}\t{count & 0xffffffff:08x}\t"
                           f"{result(mnemonic, source, count):08x}\n")


if __name__ == "__main__":
    main()
