#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Issue #16 reviewed scheduling regressions. IMAGE CASES.json [be]."""
from pathlib import Path
import json
import runpy
import struct
import sys


def main():
    image, cases = map(Path, sys.argv[1:3])
    endian = ['be'] if len(sys.argv) > 3 and sys.argv[3] == 'be' else []
    generator = Path(__file__).with_name('pipeline-schedule.py')
    sys.argv = [str(generator), str(image), *endian]
    runpy.run_path(str(generator), run_name='__main__')
    data = bytearray(image.read_bytes())
    order = '>' if endian else '<'
    struct.pack_into(order + 'HH', data, 0x1400, 0x0c6e, 0x0c6e)  # Compact NOP1, NOP1.
    struct.pack_into(order + 'I', data, 0x141c, 0xe0200000)  # First word is compact.
    struct.pack_into(order + 'II', data, 0x1420, 0x000c0362, 0x00008000)  # B B3; NOP5.
    image.write_bytes(data)
    cases.write_text(json.dumps([
        dict(name='parallel_old', entry=0x1000, inputs=dict(A3=0x44), output='A4', expected=0x44, raw=1),
        dict(name='mpysp_delay', entry=0x1100, inputs=dict(A3=0x40000000, A4=0x40400000, A5=0x55),
             output='A6', expected=0x55, raw=0x40c00000),
        dict(name='load_write_phases', entry=0x1e40, inputs=dict(A4=0x8000),
             output='A6', expected=0x8004, raw=0x22334455),
    ], indent=2) + '\n')


if __name__ == '__main__':
    main()
