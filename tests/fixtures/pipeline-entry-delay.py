#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""TI-assembled exact schedule whose entry packet issues a call: IMAGE CASES.json [be].

Requires TI's C6000 assembler (TI_C6000_BIN as in pipeline-predicate-facts.py).
cl6x 8.3.15 -mv6740 --no_compress assembles a call issued by the entry packet, its
five delay slots (B3 link, arguments), the caller return, a leaf callee, and an
outside jump into the first slot. Full32 only, so BE swaps each word's bytes.
"""
from pathlib import Path
import importlib.util
import json
import os
import subprocess
import sys

SOURCE = """ .sect ".pf_entry_delay"
 .nocmp
entry_call:
 B.S2 callee
entry_call_slot:
 MV.L2 B3,B13
 MVK.S2 0x1018,B3
 MVK.S1 5,A4
 MVK.S2 7,B4
 NOP
caller_return:
 ADD.L1X A4,B4,A4
 MV.L2 B13,B3
 B.S2 B3
 NOP 5
callee:
 B.S2 B3
 NOP 5
 .space 0xd0
outside_jump:
 B.S2 entry_call_slot
 NOP 5
"""


def main():
    if len(sys.argv) not in (3, 4) or len(sys.argv) == 4 and sys.argv[3] != "be":
        raise SystemExit("Usage: pipeline-entry-delay.py IMAGE CASES.json [be]")
    image_path, manifest_path = map(Path, sys.argv[1:3])
    image_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    prefix = image_path.parent / (image_path.stem + ".entry-delay")
    assembly, object_file, log = (Path(str(prefix) + suffix) for suffix in (".asm", ".obj", ".log"))
    assembly.write_text(SOURCE)
    binary = Path(os.environ.get("TI_C6000_BIN", "/Applications/ti/ti-cgt-c6000_8.3.15/bin"))
    compiler = binary / "cl6x" if binary.is_dir() else binary
    command = [str(compiler), "-mv6740", "--abi=eabi", "--no_compress", "-c",
               str(assembly), "--output_file=" + str(object_file)]
    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log.write_text(completed.stdout)
    if completed.returncode:
        raise RuntimeError("TI assembly failed; see " + str(log))
    spec = importlib.util.spec_from_file_location(
        "predicate_facts", Path(__file__).with_name("pipeline-predicate-facts.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    code = module.object_sections(object_file)[".pf_entry_delay"]
    if len(code) != 0x120:  # padded to a fetch packet
        raise ValueError("Unexpected entry-delay section length " + hex(len(code)))
    image = bytearray(0x200)
    image[:len(code)] = code
    if len(sys.argv) == 4:
        image = b"".join(image[index:index + 4][::-1] for index in range(0, len(image), 4))
    image_path.write_bytes(image)
    manifest = dict(entry=0x1000, body_end=0x1027, window_end=0x1017, slot=0x1004, inside=0x1018,
                    callee=0x1028, callee_end=0x102f, outside=0x1100)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print("PIPELINE_ENTRY_DELAY_FIXTURE_OK")


if __name__ == "__main__":
    main()
