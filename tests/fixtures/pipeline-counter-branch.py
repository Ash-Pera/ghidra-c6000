#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""BDEC/BPOS exact E1 counter sampling and five delay slots.

IMAGE CASES.json [be]. Authority: SPRUFE8B BDEC pp159-160 and BPOS
pp170-171; both test signed >=0, BDEC additionally decrements in E1.
"""
from pathlib import Path
import json
import struct
import sys


def branch(name, pc, target, counter=4, side=1, predicate=0, inverted=False):
    displacement = (target - (pc & ~31)) // 4
    assert -512 <= displacement < 512
    return ((predicate << 29) | (int(inverted) << 28) | (counter << 23)
            | ((displacement & 1023) << 13) | (0x1020 if name == 'BDEC' else 0x20)
            | ((side - 1) << 1))


def mv(src, dst, side=1):
    return (dst << 23) | (src << 18) | 0x940 | ((side - 1) << 1)


def mvk(value, dst, side=1):
    return (dst << 23) | ((value & 0xffff) << 7) | 0x28 | ((side - 1) << 1)


def mvkl(value, dst, side=1, predicate=0, inverted=False):
    return ((predicate << 29) | (int(inverted) << 28) | (dst << 23)
            | ((value & 31) << 18) | 0xa358 | ((side - 1) << 1))


def main():
    endian = '>' if len(sys.argv) > 3 and sys.argv[3] == 'be' else '<'
    image = bytearray(0x10000)
    cases = []

    def emit(name, operation, value, side=1, predicate=-1, inverted=False,
             predicate_write=None, counter_write=None, refused=None, complementary=False):
        entry = 0x1000 + len(cases) * 0x200
        target = entry + 0x80
        bank = 'A' if side == 1 else 'B'
        pred = predicate < 0 or bool(predicate) != inverted
        taken = pred and value < 0x80000000
        final = (value - 1) & 0xffffffff if operation == 'BDEC' and taken else value
        companions = [mv(4, 7, side)]
        if predicate_write is not None:
            companions.append(mvkl(predicate_write, 0))
        if counter_write is not None:
            companions.append(mvkl(counter_write, 4, side, 6 if complementary else 0, complementary))
            if not complementary or predicate == 0:
                final = counter_write & 0xffffffff
        first = branch(operation, entry, target, side=side,
                       predicate=6 if predicate >= 0 else 0, inverted=inverted)
        packet = [first, *companions]
        words = [word | (i < len(packet) - 1) for i, word in enumerate(packet)]
        words += [mv(4, 8, side), mvk(1, 9), mvk(2, 10), mvk(3, 11), mvk(4, 12),
                  mvk(0x11, 13), 0xc0362, 0x8000]
        for i, word in enumerate(words):
            struct.pack_into(endian + 'I', image, entry - 0x1000 + i * 4, word)
        for i, word in enumerate([mvk(0x22, 13), 0xc0362, 0x8000]):
            struct.pack_into(endian + 'I', image, target - 0x1000 + i * 4, word)
        inputs = {f'{bank}4': value}
        if predicate >= 0: inputs['A0'] = predicate
        expected = {f'{bank}4': final, f'{bank}7': value, f'{bank}8': final,
                    'A9': 1, 'A10': 2, 'A11': 3, 'A12': 4, 'A13': 0x22 if taken else 0x11}
        if predicate_write is not None: expected['A0'] = predicate_write
        row = dict(name=name, entry=entry, operation=operation, input=inputs,
                   expected=expected, expected_subtractions=1 if operation == 'BDEC' else 0)
        if refused: row['refused'] = refused
        cases.append(row)

    for operation in ['BDEC', 'BPOS']:
        for side in [1, 2]:
            for value in [0xffffffff, 0xfffffffe, 0, 1, 0x7fffffff, 0x80000000]:
                emit(f'{operation}_{side}_{value:08x}', operation, value, side)
            emit(f'{operation}_{side}_true_predicate_negative', operation, 0xffffffff,
                 side, predicate=1, predicate_write=0)
            for inverted in [False, True]:
                for predicate in [0, 1]:
                    emit(f'{operation}_{side}_predicate_{predicate}_inverted_{inverted}',
                         operation, 1, side, predicate, inverted, 1 - predicate)
    for side in [1, 2]:
        emit(f'BPOS_{side}_negative_before_parallel_zero', 'BPOS', 0xffffffff,
             side, counter_write=0)
        emit(f'BPOS_{side}_zero_before_parallel_negative', 'BPOS', 0,
             side, counter_write=-1)
        emit(f'BDEC_{side}_complementary_writer_false', 'BDEC', 1, side,
             predicate=0, counter_write=0, complementary=True)
        emit(f'BDEC_{side}_complementary_writer_true', 'BDEC', 1, side,
             predicate=1, counter_write=0, complementary=True)
        emit(f'BDEC_{side}_simultaneous_counter_writer_refused', 'BDEC', 1,
             side, counter_write=0, refused='potential simultaneous E1 writer')

    for side in [1, 2]:
        emit(f'BDEC_{side}_backward_loop', 'BDEC', 2, side)
        row = cases[-1]
        entry = row['entry']
        at = entry - 0x1000
        body = bytes(image[at:at + 40])
        image[at:at + 0x100] = bytes(0x100)
        image[at + 32:at + 32 + len(body)] = body
        struct.pack_into(endian + 'I', image, at + 32,
                         branch('BDEC', entry + 32, entry, side=side) | 1)
        row['branch_offset'] = 32
        bank = 'A' if side == 1 else 'B'
        row['expected'].update({f'{bank}4': 0xffffffff, f'{bank}7': 0xffffffff,
                                f'{bank}8': 0xffffffff, 'A13': 0x11})
        row.pop('expected_subtractions')

    # A second transfer in an earlier transfer's delay window lands two cycles
    # after it: retain the first target's first two effects, then redirect again.
    for second_value in [0, 0xffffffff]:
        entry = 0x1000 + len(cases) * 0x200
        t1, t2 = entry + 0x80, entry + 0x100
        code = {0: branch('BDEC', entry, t1), 4: mvk(1, 8),
                8: branch('BDEC', entry + 8, t2, side=2),
                12: mvk(2, 9), 16: mvk(3, 10), 20: mvk(4, 11),
                24: mvk(9, 16), 28: 0, 32: mvk(10, 17), 48: 0xc0362, 52: 0x8000,
                0x80: mvk(5, 12), 0x84: mvk(6, 13), 0x88: mvk(0x55, 15),
                0x98: 0xc0362, 0x9c: 0x8000,
                0x100: mvk(7, 14), 0x108: 0xc0362, 0x10c: 0x8000}
        for offset, word in code.items():
            struct.pack_into(endian + 'I', image, entry - 0x1000 + offset, word)
        cases.append(dict(name=f'overlap_second_{second_value:08x}', entry=entry,
                          operation='BDEC', input={'A4': 0, 'B4': second_value},
                          expected={'A4': 0xffffffff, 'B4': 0xffffffff, 'A8': 1,
                                    'A9': 2, 'A10': 3, 'A11': 4, 'A12': 5, 'A13': 6,
                                    'A14': 7 if second_value == 0 else 0,
                                    'A15': 0 if second_value == 0 else 0x55,
                                    'A16': 0, 'A17': 0}))

    # ADDKPC is prohibited even on the opposite functional-unit side.
    for operation in ['BDEC', 'BPOS']:
        entry = 0x1000 + len(cases) * 0x200
        for i, word in enumerate([branch(operation, entry, entry + 0x80) | 1,
                                  (3 << 23) | 0x162, 0xc0362, 0x8000]):
            struct.pack_into(endian + 'I', image, entry - 0x1000 + i * 4, word)
        cases.append(dict(name=operation + '_addkpc_refused', operation=operation,
                          entry=entry, input={}, expected={},
                          refused='cannot share an execute packet with ADDKPC'))
    Path(sys.argv[1]).write_bytes(image)
    Path(sys.argv[2]).write_text(json.dumps(cases, indent=2) + '\n')
    print('cases=', len(cases))


if __name__ == '__main__': main()
