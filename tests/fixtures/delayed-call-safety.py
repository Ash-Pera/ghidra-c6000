#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent PR #11 path/refusal cases. IMAGE CASES.json [be].

SPRUFE8B 3.5 and 3.12 B: predicates are sampled before delay-slot writes;
a jump's pending transfer does not suppress execution of its delay slots.
"""
from pathlib import Path
import json
import runpy
import struct
import sys

d = runpy.run_path(str(Path(__file__).with_name("delayed-call.py")))
mvk, mvkh, nop, branch = (d[k] for k in ("mvk", "mvkh", "nop", "b_s1"))
A1, NOT_A1, A2 = 0x80000000, 0x90000000, 0xa0000000
B3, B4, COPY = d["B_B3"], d["B_B4"], d["MV_B13_B3"]
CALLEE = 0x4000
words = {CALLEE: B3, CALLEE + 4: nop(5)}
cases = []


def add(name, base, site, expected, code, **extra):
    words.update(code)
    cases.append(dict(name=name, entry=base, site=site, call=expected, **extra))


def addkpc(ret, count):
    return 0x162 | ((ret // 4) << 16) | (count << 13) | (3 << 23)


for i, (name, at, ret, header, expected) in enumerate([
    ("unrelated_header", 0, 0x10, 0x1c, False),
    ("following_header", 0x18, 0x28, 0x3c, False),
    ("header_at_end", 8, 0x20, 0x1c, True),
    ("header_eight_byte_slack", 8, 0x24, 0x1c, False),
]):
    base = 0x1000 + i * 0x80
    code = {base + at: branch(base + at, CALLEE), base + at + 4: addkpc(ret, 1 if at == 8 else 4),
            base + header: 0xe0000000, base + ret: B3, base + ret + 4: nop(5)}
    add(name, base + at, base + at, expected, code)


def via(base):
    return {base: branch(base, base + 0x40), base + 4: nop(5),
            base + 8: branch(base + 8, CALLEE), base + 0xc: nop(5),
            base + 0x10: B3, base + 0x14: nop(5),
            base + 0x40: mvk(base + 0x10, 3), base + 0x44: mvkh(0, 3),
            base + 0x48: A1 | branch(base + 0x48, base + 8), base + 0x4c: nop(5),
            base + 0x50: B3, base + 0x54: nop(5)}


for i, name in enumerate(["unique_jump", "alternate_slot_jump", "external_slot_entry",
                         "slot_function_entry", "opposite_prefix", "matching_prefix",
                         "prefix_predicate_write", "taken_predicate_write", "partial_jump_window",
                         "alternate_slot_data", "taken_skipped_predicate_write", "parallel_predicate_write", "target_function_entry", "target_external_entry",
                         "target_data_reference", "interior_slot_entry", "nested_incoming_transfer",
                         "nonzero_preserving_write", "zero_preserving_write"]):
    base = 0x1200 + i * 0x80
    code = via(base)
    expected = name in ("unique_jump", "matching_prefix", "taken_skipped_predicate_write", "parallel_predicate_write",
                        "nonzero_preserving_write", "zero_preserving_write")
    extra = {}
    if name == "alternate_slot_jump":
        code.update({base + 0x60: branch(base + 0x60, base + 4), base + 0x64: nop(5)})
    if name == "target_function_entry": extra["function"] = base + 8
    if name == "target_external_entry": extra["external"] = base + 8
    if name == "target_data_reference": extra["data_reference"] = [base + 0x60, base + 8]
    if name == "interior_slot_entry": extra["external"] = base + 6
    if name == "nested_incoming_transfer":
        code.update({base + 0x4c: branch(base + 0x4c, base + 0x60),
                     base + 0x50: mvk(base + 0x10, 3), base + 0x54: nop(3)})
    if name == "external_slot_entry": extra["external"] = base + 4
    if name == "slot_function_entry": extra["function"] = base + 4
    if name == "alternate_slot_data": extra["data_reference"] = [base + 0x60, base + 4]
    if name == "opposite_prefix": code[base + 0x40] |= NOT_A1
    if name == "matching_prefix": code[base + 0x40] |= A1
    if name == "prefix_predicate_write":
        code.update({base + 0x40: NOT_A1 | mvk(base + 0x10, 3),
                     base + 0x44: mvk(1, 1) & ~2, base + 0x4c: mvkh(0, 3), base + 0x50: nop(4)})
    if name == "taken_predicate_write":
        code.update({base + 0x4c: mvk(0, 1) & ~2, base + 0x50: NOT_A1 | COPY,
                     base + 0x54: nop(3)})
    if name == "taken_skipped_predicate_write":
        code.update({base + 0x4c: NOT_A1 | (mvk(0, 1) & ~2),
                     base + 0x50: A1 | mvk(base + 0x10, 3), base + 0x54: nop(3)})
    if name == "parallel_predicate_write":
        code.update({base + 0x4c: A1 | (mvk(0, 1) & ~2) | 1,
                     base + 0x50: A1 | mvk(base + 0x10, 3), base + 0x54: nop(4)})
    if name in ("nonzero_preserving_write", "zero_preserving_write"):
        zero = name == "zero_preserving_write"
        pred = NOT_A1 if zero else A1
        code.update({base + 0x40: nop(1), base + 0x44: nop(1),
                     base + 0x48: pred | branch(base + 0x48, base + 8),
                     base + 0x4c: A2 | (mvk(0 if zero else 1, 1) & ~2),
                     base + 0x50: pred | mvk(base + 0x10, 3), base + 0x54: nop(3)})
    if name == "partial_jump_window": extra["data"] = base + 0x4c
    add(name, base, base + 8, expected, code, **extra)


for i, name in enumerate(["stable_fallthrough", "fallthrough_predicate_write", "unknown_predicate_write", "fallthrough_skipped_predicate_write"]):
    base = 0x2000 + i * 0x80
    code = {base: NOT_A1 | branch(base, base + 0x40), base + 4: mvk(CALLEE, 4),
            base + 8: mvk(base + 0x20, 3), base + 0xc: mvkh(0, 4),
            base + 0x10: mvkh(0, 3), base + 0x14: NOT_A1 | COPY,
            base + 0x18: B4, base + 0x1c: nop(5),
            base + 0x20: B3, base + 0x24: nop(5), base + 0x40: B3, base + 0x44: nop(5)}
    if name == "fallthrough_skipped_predicate_write": code[base + 0xc] = NOT_A1 | (mvk(0, 1) & ~2)
    if name == "fallthrough_predicate_write": code[base + 0xc] = mvk(0, 1) & ~2
    if name == "unknown_predicate_write":
        code[base + 8] = nop(1)
        code[base + 0x14] = A2 | mvk(base + 0x20, 3)
    add(name, base, base + 0x18, name in ("stable_fallthrough", "fallthrough_skipped_predicate_write"), code)


def main():
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image = bytearray(0x3040)
    for address, value in words.items(): struct.pack_into(endian + "I", image, address - 0x1000, value)
    Path(sys.argv[1]).write_bytes(image)
    Path(sys.argv[2]).write_text(json.dumps(cases, indent=2) + "\n")


if __name__ == "__main__": main()
