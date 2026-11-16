#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""TI cl6x native load-deferral fixture (hardware results per SPRUFE8B 3.4, 3.6, 4.2.5; docs/regressions.md): IMAGE CASES.json [be]."""
from pathlib import Path
import importlib.util
import json
import os
import subprocess
import sys

BASE = 0x1000
STRIDE = 0x100
OLD = 0x0BADF00D
WORD = 0x12345678
RET = [" B.S2 B3", " NOP 5"]


def reads_at(load, k, extra=()):
    """The load, a read of A5 into A4 k cycles later, and a read into A6 five cycles after it."""
    body = [f" {load}"] + ([f" NOP {k - 1}"] if k > 1 else []) + [" MV.L1 A5,A4"]
    body += ([f" NOP {4 - k}"] if k < 4 else []) + [" MV.L1 A5,A6", *extra]
    return body + RET


# name, kind, memory, body, runs: [(initial registers, expected registers)]
CASES = [
    *[(f"ldw_e{k}", "exact", "word", reads_at("LDW.D1T1 *A4,A5", k),
       [({}, {"A4": OLD, "A6": WORD})]) for k in (1, 2, 3, 4)],
    ("ldb_sign", "exact", "byte", reads_at("LDB.D1T1 *A4,A5", 2), [({}, {"A4": OLD, "A6": 0xFFFFFF80})]),
    ("ldbu_zero", "exact", "byte", reads_at("LDBU.D1T1 *A4,A5", 2), [({}, {"A4": OLD, "A6": 0x00000080})]),
    ("ldh_sign", "exact", "half", reads_at("LDH.D1T1 *A4,A5", 3), [({}, {"A4": OLD, "A6": 0xFFFF8001})]),
    ("ldhu_zero", "exact", "half", reads_at("LDHU.D1T1 *A4,A5", 3), [({}, {"A4": OLD, "A6": 0x00008001})]),
    ("lddw_pair", "exact", "double", [
        " LDDW.D1T1 *A4,A9:A8", " MV.L1 A8,A4", " || MV.S1 A9,A6", " NOP 3",
        " MV.L1 A8,A10", " || MV.S1 A9,A11", *RET],
     [({}, {"A4": 0x88888888, "A6": 0x99999999, "A10": 0x55667788, "A11": 0x11223344})]),
    # The predicate is sampled in E1; a false one leaves the destination unchanged (SPRUFE8B 3.6).
    ("predicated", "exact", "word", reads_at("[B0] LDW.D1T1 *A4,A5", 2),
     [({"B0": 1}, {"A4": OLD, "A6": WORD}), ({"B0": 0}, {"A4": OLD, "A6": OLD})]),
    # Parallel-read staging in the issue or landing packet: ADD reads B7 before MVK writes it.
    ("staged_issue", "exact", "word", [
        " MVK.S2 5,B7", " || ADD.L2 B7,B8,B9", " || LDW.D1T1 *A4,A5", " NOP 1",
        " MV.L1 A5,A4", " NOP 2", " MV.L1 A5,A6", *RET],
     [({"B7": 1, "B8": 0x10}, {"A4": OLD, "A6": WORD, "B9": 0x11, "B7": 5})]),
    ("staged_landing", "exact", "word", [
        " LDW.D1T1 *A4,A5", " NOP 1", " MV.L1 A5,A4", " NOP 2",
        " MVK.S2 5,B7", " || ADD.L2 B7,B8,B9", " || MV.L1 A5,A6", *RET],
     [({"B7": 1, "B8": 0x10}, {"A4": OLD, "A6": WORD, "B9": 0x11, "B7": 5})]),
    ("branch_in_window", "refused", "word", [
        " LDW.D1T1 *A4,A5", " B.S2 nll_biw_out", " MV.L1 A5,A4", " NOP 3", " MV.L1 A5,A6",
        "nll_biw_out:", *RET], []),
    ("branch_before", "refused", "word", [
        " B.S2 nll_bb_out", " LDW.D1T1 *A4,A5", " MV.L1 A5,A4", " NOP 3", " MV.L1 A5,A6",
        "nll_bb_out:", *RET], []),
    ("second_writer", "refused", "word", [
        " LDW.D1T1 *A4,A5", " MV.L1 A5,A4", " MVK.S1 7,A5", " NOP 2", " MV.L1 A5,A6", *RET], []),
    ("overlapping_loads", "refused", "word", [
        " LDW.D1T1 *A4,A5", " || LDW.D2T2 *B4,B5", " NOP 1", " MV.L1 A5,A4", " || MV.L2 B5,B6",
        " NOP 2", " MV.L1 A5,A6", *RET], []),
    # Three same-packet hazards exceed parallel staging, so the load would sample the new B0.
    ("predicate_unstaged", "refused", "word", [
        " MVK.S2 0,B0", " || MVK.S1 1,A6", " || MVK.D1 2,A7", " || [B0] LDW.D2T1 *B4,A5",
        " || ADD.L1 A6,A7,A8", " MV.L1 A5,A4", " NOP 3", " MV.L1 A5,A9", *RET], []),
    ("ldw_after", "native", "word", [" LDW.D1T1 *A4,A5", " NOP 4", " MV.L1 A5,A4", *RET],
     [({}, {"A4": WORD})]),
    ("swap_packet", "native", "word", [" MV.L1 A4,A5", " || MV.S1 A5,A4", " ADD.L1 A4,A5,A4", *RET],
     [({"A4": 3, "A5": 0x20}, {"A4": 0x23, "A5": 3})]),
]

# A branch from another function into the window between the load and its landing packet.
ENTERED = ("entered_window", [
    " B.S2 nll_enter_target", " NOP 5",
    " LDW.D1T1 *A4,A5", " NOP 1", "nll_enter_target:", " MV.L1 A5,A4", " NOP 2",
    " MV.L1 A5,A6", *RET])


def main():
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != "be"):
        raise SystemExit("Usage: native-load-latency.py IMAGE CASES.json [be]")
    spec = importlib.util.spec_from_file_location("pf", Path(__file__).with_name("pipeline-predicate-facts.py"))
    pf = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pf)
    image_path, manifest_path = map(Path, sys.argv[1:3])
    image_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    prefix = image_path.parent / (image_path.stem + ".native-load-latency")
    source_path, object_path, log_path = (Path(str(prefix) + s) for s in (".asm", ".obj", ".log"))
    sections = [("nll_" + name, body) for name, _, _, body, _ in CASES] + [("nll_" + ENTERED[0], ENTERED[1])]
    lines = []
    for tag, body in sections:
        lines += [f' .sect ".pf_{tag}"', " .nocmp", f"{tag}:", *body]
    source_path.write_text("\n".join(lines) + "\n")
    binary = Path(os.environ.get("TI_C6000_BIN", "/Applications/ti/ti-cgt-c6000_8.3.15/bin"))
    compiler = binary / "cl6x" if binary.is_dir() else binary
    command = [str(compiler), "-mv6740", "--abi=eabi", "--no_compress", "-c", str(source_path),
               "--output_file=" + str(object_path)]
    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log_path.write_text(completed.stdout)
    if completed.returncode:
        raise RuntimeError("TI assembly failed; see " + str(log_path))
    objects = pf.object_sections(object_path)
    image = bytearray(len(sections) * STRIDE)
    manifest = []
    for index, (tag, _) in enumerate(sections):
        data = objects[".pf_" + tag]
        if len(data) > STRIDE or len(data) % 4:
            raise ValueError(f"Invalid full32 fixture section {tag}: {len(data)} bytes")
        image[index * STRIDE:index * STRIDE + len(data)] = data
        entry = BASE + index * STRIDE
        if index < len(CASES):
            name, kind, memory, _, runs = CASES[index]
            manifest.append(dict(name=name, kind=kind, memory=memory, entry=entry, length=len(data),
                                 runs=[dict(initial=i, expected=e) for i, e in runs]))
        else:
            manifest.append(dict(name=ENTERED[0], kind="refused", memory="word", entry=entry + 8,
                                 length=len(data) - 8, runs=[], source=entry, source_length=8))
    if len(sys.argv) == 4:
        image = b"".join(image[i:i + 4][::-1] for i in range(0, len(image), 4))
    image_path.write_bytes(image)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"NATIVE_LOAD_LATENCY_FIXTURE_OK cases={len(manifest)}")


if __name__ == "__main__":
    main()
