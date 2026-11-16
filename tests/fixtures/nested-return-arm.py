#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build nested call/return arms with cl6x. Usage: IMAGE [be]."""
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
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "be"):
        raise SystemExit(__doc__)
    image_path = Path(sys.argv[1])
    image_path.parent.mkdir(parents=True, exist_ok=True)
    source_path = Path(__file__).with_name("nested-return-arm.asm")
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
    image = bytearray(object_sections(object_path)[".pf_nested_return_arm"])
    if len(image) < 56 or len(image) % 4:
        raise ValueError("Unexpected nested return-arm section size")
    if len(sys.argv) == 3:
        image = b"".join(image[index:index + 4][::-1] for index in range(0, len(image), 4))
    image_path.write_bytes(image)
    print("NESTED_RETURN_ARM_FIXTURE_OK")


if __name__ == "__main__":
    main()
