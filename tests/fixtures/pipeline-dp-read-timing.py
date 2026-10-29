#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ADDDP/SUBDP read phases, SPRUFE8B Table 4-16 / SPRU733A Table 4-12.

IMAGE CASES.json [be]. Both low words are sampled in E1 and both high words
in E2, before writes in that cycle. Arithmetic uses the rational DP oracle.
"""
from pathlib import Path
import importlib.util
import json
import struct
import sys

sys.dont_write_bytecode = True

# Manual opcode fields, including the alternate src1-cross .L subtraction
# and the .S encoding that reverses the displayed subtraction operands.
FORMS = [("add_l", 0x318, "L", False), ("add_s", 0xe58, "S", False),
         ("sub_l", 0x338, "L", False), ("sub_l_src1", 0x3b8, "L", False),
         ("sub_s", 0xe78, "S", False), ("sub_s_reversed", 0xef8, "S", True)]


def main():
    spec = importlib.util.spec_from_file_location("dp_oracle", Path(__file__).with_name("float-dp-arithmetic.py"))
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    endian = ">" if len(sys.argv) > 3 and sys.argv[3] == "be" else "<"
    image, rows = bytearray(), []

    def emit(form, side, producer, port, cross=False, enabled=True):
        name, opcode, unit, reverse = form
        bank = "A" if side == 1 else "B"
        source_banks = [bank, bank]
        if cross: source_banks[port] = "B" if side == 1 else "A"
        writer_bank = source_banks[port]
        writer_side = 1 if writer_bank == "A" else 2
        low = 2 * port
        high = low + 1
        destination = 0 if producer == "multiply" or (producer == "load" and side == 2) else 2 if producer == "load" else 4
        inputs = {"A31": 0x9000, "FADCR": 0,
                  source_banks[0] + "0": 0, source_banks[0] + "1": 0x3ff00000,
                  source_banks[1] + "2": 0, source_banks[1] + "3": 0x40100000,
                  writer_bank + "22": 0x40000000}
        if destination == 4: inputs.update({bank + "4": 0x11111111, bank + "5": 0x22222222})
        # MVKH on .S, ADD-zero on .L: a legal companion to either DP unit.
        writer = ((high << 23) | (0x4000 << 7) | 0x68 | (writer_side - 1) * 2) if unit == "L" else ((high << 23) | (22 << 18) | 0x58 | (writer_side - 1) * 2)
        dp = opcode | (side - 1) * 2 | (2 << 18) | (destination << 23) | (0x1000 if cross else 0)
        first, second = 0x3ff0000000000000, 0x4010000000000000
        prefix, memory = [], None
        if producer == "multiply":
            inputs.update({writer_bank + "20": 0x8000, writer_bank + "21": 0x8000})
            prefix = [(high << 23) | (20 << 13) | (21 << 18) | 0xc80 | (writer_side - 1) * 2]
        elif producer == "load":
            inputs[writer_bank + "24"] = 0x8000
            prefix = [(high << 23) | (24 << 18) | 0x264 | (0x82 if writer_side == 2 else 0), 0x4000]  # LDW; NOP 3
            memory = {str(0x8000): 0x40000000}
        if producer in ("parallel", "multiply", "load", "predicate"):
            if port == 0: first = 0x4000000000000000
            else: second = 0x4000000000000000
        if producer == "predicate":
            dp |= 0x80000000 if side == 1 else 0x40000000  # [A1] / [B1], aliases src1_h
            inputs[bank + "1"] = 0x3ff00000 if enabled else 0
        if producer == "low":
            writer = (low << 23) | (1 << 7) | 0x28 | (writer_side - 1) * 2
            # .S companion requires an .L DP instruction.
        if producer in ("parallel", "predicate", "low"):
            words = prefix + [dp | 1, writer]
        elif producer == "late":
            words = [dp, writer]  # E2 writer commits after E2 operand sampling
        else:
            words = prefix + [dp]
        words += [0xe000, (3 << 23) | (31 << 18) | 0x105a, 0xc0362, 0x8000]  # NOP 8; MV A31,B3; return
        output, flags = oracle.addsub(first, second, 0, name.startswith("sub"), reverse)
        expected = {bank + str(destination): output & 0xffffffff,
                    bank + str(destination + 1): output >> 32,
                    "FADCR": flags << (0 if side == 1 else 16), "PC": 0x9000}
        if producer == "predicate" and not enabled:
            expected = {bank + "4": 0x11111111, bank + "5": 0x22222222, "FADCR": 0, "PC": 0x9000}
        index = len(rows)
        image.extend(struct.pack(endian + str(len(words)) + "I", *words) + bytes(128 - 4 * len(words)))
        row = dict(name=f"{name}_{side}_{producer}_port{port}" + ("_cross" if cross else "") + ("_false" if not enabled else ""),
                   entry=0x1000 + 128 * index, extent=127, input=inputs, expected=expected,
                   expected_stalls=1 if cross and producer == "parallel" else 0)
        if memory: row["memory"] = memory
        if name in ("add_l", "sub_s_reversed") and side == 1 and producer == "parallel" and port == 0:
            row.update(decompile=True, double_return=True)
        rows.append(row)

    for form in FORMS:
        for side in (1, 2):
            for port in (0, 1):
                for producer in ("parallel", "multiply", "load", "late"):
                    emit(form, side, producer, port)
            # A low-word E1 reader must retain its issue snapshot.
            # .S DP uses an .L copy for the upper-word tests; use .L forms here.
            if form[2] == "L":
                for port in (0, 1): emit(form, side, "low", port)
            emit(form, side, "predicate", 0)
            emit(form, side, "predicate", 0, enabled=False)
    for form, port in ((FORMS[0], 1), (FORMS[3], 0)):
        for side in (1, 2):
            for producer in ("parallel", "multiply", "load"):
                emit(form, side, producer, port, cross=True)
    Path(sys.argv[1]).write_bytes(image)
    Path(sys.argv[2]).write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__": main()
