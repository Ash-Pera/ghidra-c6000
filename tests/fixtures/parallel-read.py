#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Self-written parallel-read packets. Usage: IMAGE CASES.json [be]."""
from pathlib import Path
import json
import struct
import sys


def pred(creg=0, invert=False):
    return (creg << 29) | (int(invert) << 28)


def mv(src, dst, side=1, cross=False, p=0, condition=0, invert=False):
    return ((dst << 23) | (src << 18) | (int(cross) << 12) | 0x58 |
            ((side - 1) << 1) | pred(condition, invert) | p)


def add_rr(src1, src2, dst, side=1, cross=False, p=0, condition=0,
           invert=False):
    return ((dst << 23) | (src2 << 18) | (src1 << 13) |
            (int(cross) << 12) | 0x78 | ((side - 1) << 1) |
            pred(condition, invert) | p)


def sub_rr(src1, src2, dst, cross=False):
    return ((dst << 23) | (src2 << 18) | (src1 << 13) |
            (int(cross) << 12) | 0xf8)


def add_imm5(value, src, dst, side=1, p=0, condition=0, invert=False):
    return ((dst << 23) | (src << 18) | ((value & 31) << 13) |
            0x58 | ((side - 1) << 1) | pred(condition, invert) | p)


def mvk(value, dst, condition=0, invert=False, p=0):
    return ((dst << 23) | ((value & 0xffff) << 7) | 0x28 |
            pred(condition, invert) | p)


def mpy(src1, src2, dst, p=0):
    return ((dst << 23) | (src2 << 18) | (src1 << 13) | 0xc80 | p)


def branch(displacement, side=2, condition=0, invert=False):
    return ((displacement << 7) | 0x10 | ((side - 1) << 1) |
            pred(condition, invert))


def put(image, base, address, words, endian):
    for index, word in enumerate(words):
        struct.pack_into(endian + "I", image, address - base + index * 4, word)


def main():
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != "be"):
        raise SystemExit(__doc__)
    base = 0x1000
    image = bytearray(0x800)
    endian = ">" if len(sys.argv) == 4 else "<"

    swap = 0x1000
    put(image, base, swap, [
        mv(4, 4, side=1, cross=True, p=1),
        mv(4, 4, side=2, cross=True),
        add_rr(4, 4, 4),
        sub_rr(4, 4, 4, cross=True),
        0x000c0332,
        0x00008000,
    ], endian)

    predicated = 0x1100
    put(image, base, predicated, [
        mvk(0x1234, 4, condition=1, p=1),
        add_imm5(1, 4, 4, condition=1, invert=True, p=1),
        mv(4, 5, side=2, cross=True),
    ], endian)

    multicycle = 0x1200
    put(image, base, multicycle, [
        mpy(2, 3, 4, p=1),
        mv(4, 6, side=2, cross=True),
        mv(4, 7, side=2, cross=True),
    ], endian)

    loop = 0x1300
    put(image, base, loop, [
        add_imm5(-1, 1, 1, side=2, condition=2, p=1),
        branch(0, side=2, condition=2),
        mv(1, 6, side=2),
        0,
        0,
        0,
        0,
    ], endian)

    jump_prime = 0x1400
    jump_late = 0x1500
    for entry in (jump_prime, jump_late):
        put(image, base, entry, [branch(9, side=1)], endian)
        put(image, base, entry + 0x20, [
            mv(4, 4, side=1, cross=True, p=1),
            mv(4, 4, side=2, cross=True),
        ], endian)

    # A control-transfer member that is not last in its packet, beside a
    # read-after-write between two data members. The reader must still see the
    # old value; the branch neither reads nor writes the staged register.
    branch_mid = 0x1600
    put(image, base, branch_mid, [
        branch(8, side=1) | 1,
        add_rr(4, 5, 6, p=1),
        add_imm5(8, 6, 7),
        0, 0, 0, 0,
    ], endian)

    runs = [
        dict(name="swap", sequence=[swap, swap + 4, swap + 8, swap + 12],
             input={"A4": 3, "B4": 9}, expected={"A4": 15, "B4": 3}),
        dict(name="branch_not_last", sequence=[branch_mid + 4, branch_mid + 8],
             input={"A4": 3, "A5": 4, "A6": 100},
             expected={"A6": 7, "A7": 108}),
        dict(name="predicate_true", sequence=[predicated, predicated + 4,
             predicated + 8], input={"A4": 5, "B0": 1},
             expected={"A4": 0x1234, "B5": 5}),
        dict(name="predicate_false", sequence=[predicated, predicated + 4,
             predicated + 8], input={"A4": 5, "B0": 0},
             expected={"A4": 6, "B5": 5}),
        dict(name="multicycle_cross_packet", sequence=[multicycle,
             multicycle + 4, multicycle + 8],
             input={"A2": 7, "A3": 9, "A4": 0x21},
             expected={"A4": 63, "B6": 0x21, "B7": 63}),
    ]
    jumps = [
        dict(name="jump_seen_at_prime", source=jump_prime, packet=jump_prime + 0x20,
             target=jump_prime + 0x24, timing="prime"),
        dict(name="jump_seen_after_analysis", source=jump_late, packet=jump_late + 0x20,
             target=jump_late + 0x24, timing="late"),
    ]
    cases = dict(runs=runs, branch=dict(entry=loop, delay_bytes=20),
                 jumps=jumps)
    Path(sys.argv[1]).write_bytes(image)
    Path(sys.argv[2]).write_text(json.dumps(cases, indent=2) + "\n")


if __name__ == "__main__":
    main()
