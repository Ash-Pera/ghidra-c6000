#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build nested-return predicate cases with cl6x. Usage: IMAGE CASES.tsv [be]."""
from pathlib import Path
import importlib.util
import os
import subprocess
import sys


def object_sections(path):
    helper = Path(__file__).with_name("pipeline-predicate-facts.py")
    spec = importlib.util.spec_from_file_location("predicate_facts", helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.object_sections(path)


def main():
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != "be"):
        raise SystemExit(__doc__)
    image_path = Path(sys.argv[1])
    cases_path = Path(sys.argv[2])
    image_path.parent.mkdir(parents=True, exist_ok=True)
    cases_path.parent.mkdir(parents=True, exist_ok=True)
    source_path = Path(__file__).with_name("overwritten-arm-predicate.asm")
    object_path = image_path.with_suffix(".obj")
    log_path = image_path.with_suffix(".asm.log")
    binary = Path(os.environ.get("TI_C6000_BIN", "/Applications/ti/ti-cgt-c6000_8.3.15/bin"))
    compiler = binary / "cl6x" if binary.is_dir() else binary
    result = subprocess.run(
        [str(compiler), "-mv6740", "--abi=eabi", "-c", str(source_path),
         "--output_file=" + str(object_path)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    log_path.write_text(result.stdout)
    if result.returncode:
        raise RuntimeError("TI assembly failed; see " + str(log_path))
    sections = object_sections(object_path)
    names = (
        "overwritten_arm", "bad_unimplied", "bad_later_write", "bad_non_nop_tail",
        "bad_first_packet", "bad_extra_jump", "bad_peer_link",
    )
    image = bytearray()
    cases = []
    for name in names:
        image.extend(b"\0" * (-len(image) % 32))
        section = sections.get(".pf_" + name)
        if section is None or not section or len(section) % 4:
            raise ValueError("Unexpected section size for " + name)
        start = 0x1000 + len(image)
        image.extend(section)
        cases.append(f"{name}\t{start:08x}\t{start + len(section):08x}")
    cases_path.write_text("\n".join(cases) + "\n")
    if len(image) % 4:
        raise ValueError("Unexpected overwritten-arm-predicate image size")
    if len(sys.argv) == 4:
        image = b"".join(image[index:index + 4][::-1] for index in range(0, len(image), 4))
    image_path.write_bytes(image)
    print("OVERWRITTEN_ARM_PREDICATE_FIXTURE_OK")


if __name__ == "__main__":
    main()
