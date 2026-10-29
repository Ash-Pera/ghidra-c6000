#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""PACK2/PACKL4 E1 reads/writeback, SPRUFE8B pp.397-398,407-408. IMAGE CASES.json [be]."""
import json
from pathlib import Path
import struct
import sys


def pack(operation, unit, side, cross, src1=4, src2=5, dst=6, predicate=0):
    # SPRUFE8B PACK2 (.L/.S) and PACKL4 (.L) opcode maps.
    opcode = {('PACK2','L'): 0x18, ('PACK2','S'): 0xff0, ('PACKL4','L'): 0xd18}[operation,unit]
    return predicate << 28 | dst << 23 | src2 << 18 | src1 << 13 | cross << 12 | opcode | side << 1


def packed(operation, a, b):
    if operation == 'PACK2':
        return (a & 0xffff) << 16 | b & 0xffff
    return ((a >> 16 & 255) << 24 | (a & 255) << 16 |
            (b >> 16 & 255) << 8 | b & 255)


def move(src, dst, side, unit='L'):
    return dst << 23 | src << 18 | {'L': 0xfd8, 'S': 0x6a0}[unit] | side << 1


def main():
    if len(sys.argv) not in (3, 4) or len(sys.argv) == 4 and sys.argv[3] != 'be':
        raise SystemExit(__doc__)
    endian = '>' if len(sys.argv) == 4 else '<'
    image = bytearray(0x8000)
    rows = []

    def emit(name, word, inputs, result, dst=6, side=0, companions=(), expected=None, refused=None):
        bank = 'AB'[side]
        packet = [word, *companions]
        packet = [w | int(i < len(packet) - 1) for i, w in enumerate(packet)]
        words = packet + [move(dst, 9, side), 0x008ca362]
        entry = 0x1000 + len(rows) * 0x80
        for i, w in enumerate(words):
            struct.pack_into(endian + 'I', image, entry - 0x1000 + 4 * i, w)
        row = dict(name=name, operation=operation, entry=entry, input=inputs,
                   expected={f'{bank}{dst}': result, f'{bank}9': result,
                             'PC': 0x9000, 'AMR': 0x12345678, 'CSR': 0x2468,
                             **(expected or {})},
                   raw_destination=f'{bank}{dst}', raw_expected=result)
        if refused:
            row['refused'] = refused
        rows.append(row)

    for operation, unit in [('PACK2','L'), ('PACK2','S'), ('PACKL4','L')]:
        for side in (0, 1):
            bank = 'AB'[side]
            peer = 'S' if unit == 'L' else 'L'
            for cross in (0, 1):
                other = 'AB'[side ^ cross]
                for dst, same in ((6, False), (4, False), (5, False), (4, True)):
                    src2 = 4 if same else 5
                    inputs = {f'{bank}4': 0x195721ab, f'{other}{src2}': 0x081c17e6}
                    inputs.setdefault(f'{bank}{dst}', 0x13579bdf)
                    result = packed(operation, inputs[f'{bank}4'], inputs[f'{other}{src2}'])
                    emit(f'{operation}_{unit}{side+1}_x{cross}_dst{dst}_same{same}',
                         pack(operation, unit, side, cross, src2=src2, dst=dst), inputs, result, dst, side)

                # Predicates must use their incoming value even if a parallel
                # instruction changes the predicate register during E1.
                for creg, preg, pside in ((6, 'A0', 0), (1, 'B0', 1)):
                    for inverted in (0, 1):
                        for value in (0, 1, 0xffffffff):
                            enabled = (value == 0) if inverted else value != 0
                            inputs = {f'{bank}4': 0x195721ab, f'{other}5': 0x081c17e6,
                                      f'{bank}6': 0x13579bdf, preg: value,
                                      f'{"AB"[pside]}10': int(value == 0)}
                            writer_unit = peer if pside == side else 'L'
                            companion = move(10, 0, pside, writer_unit)
                            emit(f'{operation}_{unit}{side+1}_x{cross}_{preg}_z{inverted}_v{value:x}',
                                 pack(operation, unit, side, cross, predicate=2*creg+inverted), inputs,
                                 packed(operation, 0x195721ab, 0x081c17e6) if enabled else 0x13579bdf, side=side,
                                 companions=[companion], expected={preg: int(value == 0)})

                # Parallel writers must not change either captured input.
                for which in (1, 2):
                    writer_side = side if which == 1 else side ^ cross
                    writer_reg = 4 if which == 1 else 5
                    writer_bank = 'AB'[writer_side]
                    writer_unit = peer if writer_side == side else 'L'
                    inputs = {f'{bank}4': 0x195721ab, f'{other}5': 0x081c17e6,
                              f'{writer_bank}10': 0xffffffff}
                    emit(f'{operation}_{unit}{side+1}_x{cross}_capture_src{which}', pack(operation, unit, side, cross),
                         inputs, packed(operation, 0x195721ab, 0x081c17e6), side=side,
                         companions=[move(10, writer_reg, writer_side, writer_unit)],
                         expected={f'{writer_bank}{writer_reg}': 0xffffffff})

                # A same-packet consumer sees the old destination; a consumer
                # in the following cycle sees the E1 PACK2/PACKL4 result.
                emit(f'{operation}_{unit}{side+1}_x{cross}_writeback_e1', pack(operation, unit, side, cross),
                     {f'{bank}4': 0x195721ab, f'{other}5': 0x081c17e6,
                      f'{bank}6': 0x13579bdf}, packed(operation, 0x195721ab, 0x081c17e6), side=side,
                     companions=[move(6, 8, side, peer)], expected={f'{bank}8': 0x13579bdf})
            emit(f'{operation}_{unit}{side+1}_unit_collision', pack(operation, unit, side, 0), {}, 0, side=side,
                 companions=[pack(operation, unit, side, 0, dst=7)], refused='functional-unit collision')

    assert len(rows) == 234
    Path(sys.argv[1]).write_bytes(image)
    Path(sys.argv[2]).write_text(json.dumps(rows, indent=2) + '\n')


if __name__ == '__main__':
    main()
