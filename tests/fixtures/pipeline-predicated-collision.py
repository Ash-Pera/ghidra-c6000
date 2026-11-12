#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stock-free same-cycle write fixture: IMAGE CASES.json [be].

An in-flight load and a later E1 writer of one register land in the same cycle.
Complementary predicates sampling one unchanged value never both execute, so the
schedule is exact; any other pair stays refused. Requires TI's C6000 assembler
(TI_C6000_BIN, as pipeline-predicate-facts.py). Full32 .nocmp only.
"""
from pathlib import Path
import importlib.util
import json
import os
import subprocess
import sys

# name, accepted, body; B4 points at the word 1, the function returns with B5.
specs = [
    ('complementary', True, [' [!B0] LDW.D2 *B4,B5', ' NOP 3', ' [B0] MVK.S2 7,B5']),
    ('complementary_copy', True, [' [!B0] LDW.D2 *B4,B5', ' || MV.L2 B0,B2', ' NOP 3', ' [B2] MVK.S2 7,B5']),
    ('complementary_load_last', True, [' [B0] MVK.S2 7,B6', ' [!B0] LDW.D2 *B4,B5', ' NOP 3', ' [B0] MV.L2 B6,B5']),
    ('rewritten_between', False, [' [!B0] LDW.D2 *B4,B5', ' MV.L2 B6,B0', ' NOP 2', ' [B0] MVK.S2 7,B5']),
    ('copy_of_new_value', False, [' [!B0] LDW.D2 *B4,B5', ' MV.L2 B6,B0', ' MV.L2 B0,B2', ' NOP', ' [B2] MVK.S2 7,B5']),
    ('same_sense', False, [' [!B0] LDW.D2 *B4,B5', ' NOP 3', ' [!B0] MVK.S2 7,B5']),
    ('other_register', False, [' [!B0] LDW.D2 *B4,B5', ' NOP 3', ' [B1] MVK.S2 7,B5']),
    ('unpredicated', False, [' LDW.D2 *B4,B5', ' NOP 3', ' MVK.S2 7,B5']),
]


def main():
    if len(sys.argv) not in (3, 4) or len(sys.argv) == 4 and sys.argv[3] != 'be':
        raise SystemExit('Usage: pipeline-predicated-collision.py IMAGE CASES.json [be]')
    spec = importlib.util.spec_from_file_location('pf', Path(__file__).with_name('pipeline-predicate-facts.py'))
    pf = importlib.util.module_from_spec(spec); spec.loader.exec_module(pf)
    image_path, manifest_path = map(Path, sys.argv[1:3])
    image_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    prefix = image_path.parent / (image_path.stem + '.predicated-collision')
    source_path, object_path, log_path = (Path(str(prefix) + suffix) for suffix in ('.asm', '.obj', '.log'))
    lines, manifest = [], []
    for index, (name, accepted, body) in enumerate(specs):
        tag = 'pf_' + name
        lines += [' .sect ".' + tag + '"', ' .nocmp', tag + ':'] + body + [' NOP 5', ' B.S2 B3', ' NOP 5']
        manifest.append(dict(name=name, at=0x1000 + index * 256, accepted=accepted))
    source_path.write_text('\n'.join(lines) + '\n')
    binary = Path(os.environ.get('TI_C6000_BIN', '/Applications/ti/ti-cgt-c6000_8.3.15/bin'))
    compiler = binary / 'cl6x' if binary.is_dir() else binary
    command = [str(compiler), '-mv6740', '--abi=eabi', '-c', str(source_path), '--output_file=' + str(object_path)]
    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log_path.write_text(completed.stdout)
    if completed.returncode:
        raise RuntimeError('TI assembly failed; see ' + str(log_path))
    sections = pf.object_sections(object_path)
    image = bytearray(len(specs) * 256)
    for index, item in enumerate(manifest):
        data = sections['.pf_' + item['name']]
        if len(data) > 256 or len(data) % 4:
            raise ValueError('Invalid full32 fixture section length')
        image[index * 256:index * 256 + len(data)] = data
    if len(sys.argv) == 4:
        image = b''.join(image[index:index + 4][::-1] for index in range(0, len(image), 4))
    image_path.write_bytes(image)
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
    print('PREDICATED_COLLISION_FIXTURE_OK cases=' + str(len(manifest)))


if __name__ == '__main__':
    main()
