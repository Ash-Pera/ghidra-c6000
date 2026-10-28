#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ROTL E1 reads/E2 writeback, SPRUFE8B pp.414--415. IMAGE CASES.json [be]."""
from pathlib import Path
import json, struct, sys


def rotate(value, count):
    # Independent bit-string oracle: src1's low five bits select the cut.
    bits = f'{value:032b}'
    cut = count % 32
    return int(bits[cut:] + bits[:cut], 2)


def rotl(src2, src1, dst, side=1, immediate=False, cross=False, predicate=0):
    # SPRUFE8B ROTL opcode table, p.414: displayed src2,src1,dst.
    return ((predicate << 29) | (dst << 23) | (src2 << 18) |
            (src1 << 13) | (int(cross) << 12) |
            (0x7b0 if immediate else 0x770) | (2 if side == 2 else 0))


def mv(src, dst, side=1):
    return (dst << 23) | (src << 18) | 0x58 | (2 if side == 2 else 0)


def main():
    endian = '>' if len(sys.argv) > 3 and sys.argv[3] == 'be' else '<'
    image = bytearray(0x3000)
    rows = []

    def emit(name, words, inputs, expected, **extra):
        entry = 0x1000 + len(rows) * 0x100
        for index, word in enumerate(words):
            struct.pack_into(endian + 'I', image, entry - 0x1000 + index * 4, word)
        rows.append(dict(name=name, entry=entry, input=inputs, expected=expected,
                         words=[f'{word:08x}' for word in words], **extra))

    def observed(name, word, inputs, result, dst=4, side=1, companions=()):
        bank = 'B' if side == 2 else 'A'
        old = inputs.setdefault(f'{bank}{dst}', 0x0badcafe)
        packet = [word, *companions]
        packet = [value | (1 if index < len(packet) - 1 else 0)
                  for index, value in enumerate(packet)]
        emit(name, packet + [mv(dst, 8, side), mv(dst, 9, side), 0xc0362, 0x8000],
             inputs, {f'{bank}{dst}': result, f'{bank}8': old, f'{bank}9': result},
             raw_destination=f'{bank}{dst}', raw_expected=result)

    for side, bank in [(1, 'A'), (2, 'B')]:
        for count in [0, 31, 32]:
            observed(f'register_{bank}_count_{count}', rotl(2, 3, 4, side),
                     {f'{bank}2': 0x81234567, f'{bank}3': count},
                     rotate(0x81234567, count), side=side)
        for count in [0, 31]:
            observed(f'immediate_{bank}_count_{count}', rotl(2, count, 4, side, True),
                     {f'{bank}2': 0x81234567}, rotate(0x81234567, count), side=side)

    observed('manual_register_example', rotl(2, 4, 5, 2),
             {'B2': 0xa6e2c179, 'B4': 0x14583b69}, 0xc582f34d, dst=5, side=2)
    observed('manual_immediate_example', rotl(4, 16, 5, immediate=True),
             {'A4': 0x187a65fc}, 0x65fc187a, dst=5)
    for dst in [2, 3]:
        observed(f'destination_alias_src{2 if dst == 2 else 1}', rotl(2, 3, dst),
                 {'A2': 0x89abcdef, 'A3': 4}, 0x9abcdef8, dst=dst)
    observed('destination_alias_both_sources', rotl(2, 2, 2),
             {'A2': 0x12345678}, 0x78123456, dst=2)

    # Both sources change in E1 companions: ROTL must retain their old values.
    observed('crosspath_and_count_captured_e1', rotl(2, 3, 4, cross=True),
             {'B2': 0x81234567, 'A3': 31, 'B6': 0, 'A7': 0}, 0xc091a2b3,
             companions=[mv(6, 2, 2), mv(7, 3)])
    # The false/true predicate changes after E1; it must not be resampled at E2.
    observed('true_predicate_captured_e1', rotl(2, 3, 4, predicate=6),
             {'A0': 1, 'A2': 0x89abcdef, 'A3': 4, 'A6': 0}, 0x9abcdef8,
             companions=[mv(6, 0)])
    observed('false_predicate_captured_e1', rotl(2, 3, 4, predicate=6),
             {'A0': 0, 'A2': 0x89abcdef, 'A3': 4, 'A4': 0x0badcafe, 'A6': 1},
             0x0badcafe, companions=[mv(6, 0)])
    # .M is occupied only in E1: a new ROTL can issue on the following cycle.
    emit('consecutive_m1_issues', [rotl(2, 3, 4), rotl(10, 3, 5),
                                 mv(4, 8), mv(5, 9), 0xc0362, 0x8000],
         {'A2': 0x89abcdef, 'A3': 4, 'A10': 0x12345678},
         {'A4': 0x9abcdef8, 'A5': 0x23456781, 'A8': 0x9abcdef8, 'A9': 0x23456781},
         raw_destination='A4', raw_expected=0x9abcdef8)
    emit('same_m1_packet_refused', [rotl(2, 3, 4) | 1, rotl(10, 3, 5),
                                    0xc0362, 0x8000], {}, {},
         refused='functional-unit collision')
    Path(sys.argv[1]).write_bytes(image)
    Path(sys.argv[2]).write_text(json.dumps(rows, indent=2) + '\n')


if __name__ == '__main__':
    main()
