#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stack stores under masked STW in an exact schedule (SPRUFE8B STW): IMAGE CASES.json [be]. TI assembled, no firmware bytes."""
import importlib.util, json, os, subprocess, sys
from pathlib import Path

SLOT = 0x100
# name, body, (B15 stores, masked stores, CALLINDs); table_walk saves its cursor on the stack in a register call's delay slots
CASES = [
    ("table_walk",
     [" LDW.D1T1 *A4,A2", " STW.D2T2 B3,*B15--[2]", " NOP 3",
      "{tag}_loop:", " CMPEQ.L1 0,A2,A1",
      " [A1] B.S2 {tag}_done", " [!A1] B.S2X A2", " [!A1] ADD.D1 A4,4,A4", " [!A1] STW.D2T1 A4,*B15--[2]",
      " [!A1] ADDKPC.S2 {tag}_back,B3,0", " NOP 2",
      "{tag}_back:", " LDW.D2T1 *++B15[2],A4", " NOP 3", " B.S2 {tag}_loop", " LDW.D1T1 *A4,A2", " NOP 4",
      "{tag}_done:", " LDW.D2T2 *++B15[2],B3", " NOP 4", " B.S2 B3", " NOP 5"], (2, 0, 1)),
    # Every B15 store form, short and 15-bit, beside masked controls through A4 and B6.
    ("sp_forms",
     [" STW.D2T2 B3,*B15--[4]", " STH.D2T2 B4,*+B15[3]", " STDW.D2T2 B5:B4,*+B15[1]", " STW.D2T2 B4,*+B15[40]",
      " STH.D2T2 B4,*+B15[100]", " STW.D1T1 A5,*+A4[2]", " STW.D2T2 B4,*+B6[2]", " LDW.D2T2 *++B15[4],B3", " NOP 4", " B.S2 B3", " NOP 5"], (5, 2, 0)),
]


def main():
    if len(sys.argv) not in (3, 4) or len(sys.argv) == 4 and sys.argv[3] != "be":
        raise SystemExit("Usage: store-mask-schedule.py IMAGE CASES.json [be]")
    image_path, manifest_path = map(Path, sys.argv[1:3])
    big = len(sys.argv) == 4
    spec = importlib.util.spec_from_file_location("continuation", Path(__file__).with_name("pipeline-caller-continuation.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    lines, rows = [], []
    for index, (name, body, counts) in enumerate(CASES):
        tag = "ct_store_sched_" + str(index)
        lines += [' .sect ".' + tag + '"', " .nocmp", tag + ":"] + [line.format(tag=tag) for line in body]
        rows.append(dict(name=name, tag=tag, entry=0x1000 + index * SLOT, sp=counts[0], masked=counts[1], calls=counts[2]))
    image_path.parent.mkdir(parents=True, exist_ok=True)
    asm, obj = image_path.with_suffix(".asm"), image_path.with_suffix(".obj")
    asm.write_text("\n".join(lines) + "\n")
    cl6x = Path(os.environ.get("TI_C6000_BIN", "/Applications/ti/ti-cgt-c6000_8.3.15/bin")) / "cl6x"
    result = subprocess.run([str(cl6x), "-mv6740", "--abi=eabi", "-c", str(asm), "--output_file=" + str(obj)],
                            capture_output=True, text=True)
    image_path.with_suffix(".asm.log").write_text(result.stdout + result.stderr)
    assert result.returncode == 0, result.stdout + result.stderr
    sections = module.object_sections(obj)
    image = bytearray(len(rows) * SLOT)
    for row in rows:
        raw = sections["." + row["tag"]]
        assert len(raw) <= SLOT and len(raw) % 4 == 0
        if big:
            raw = b"".join(raw[k:k + 4][::-1] for k in range(0, len(raw), 4))
        at = row["entry"] - 0x1000
        image[at:at + len(raw)] = raw
        row["size"] = len(raw)
    image_path.write_bytes(image)
    manifest_path.write_text(json.dumps(rows, indent=2) + "\n")
    print("store-mask-schedule cases", len(rows))


if __name__ == "__main__":
    main()
