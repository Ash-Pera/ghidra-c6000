#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Retimed MPYSP cases, preserving the existing independent expectations.

Usage: IMAGE CASES.tsv [be]. Clear FMCR after issue but before E4 writeback;
check captured rounding modes, special values, both lanes and aliased results.
"""
from pathlib import Path
import importlib.util
import struct
import sys
sys.dont_write_bytecode = True


def main():
    image, manifest = map(Path, sys.argv[1:3])
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    spec = importlib.util.spec_from_file_location("mpysp_cases", Path(__file__).with_name("mpysp.py"))
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    with image.open("wb") as binary, manifest.open("w") as rows:
        index = 0
        for side in (1, 2):
            bank = "A" if side == 1 else "B"
            other = "B" if side == 1 else "A"
            for mode in range(4):
                for number, (left, right, outputs, flags) in enumerate(oracle.CASES):
                    alias = number % 2 == 0
                    destination = 1 if alias else 4
                    cross = number == 1
                    word = (oracle.opcode(side, cross) & ~(31 << 23)) | (destination << 23)
                    move = lambda dst: (dst << 23) | (destination << 18) | (0x58 if side == 1 else 0x5a)
                    words = [word, (20 << 23) | (7 << 18) | 0x3a2, move(6), 0,
                             move(7), 0xc0362, 0x8000]
                    binary.write(struct.pack(endian + "7I", *words) + bytes(64 - 28))
                    rows.write(f"{index}\t{bank}1\t{other if cross else bank}2\t{bank}{destination}\t{bank}6\t{bank}7\t{left:x}\t{right:x}\t{outputs[mode]:x}\t{mode << (9 if side == 1 else 25):x}\t{flags << (0 if side == 1 else 16):x}\n")
                    index += 1


if __name__ == "__main__":
    main()
