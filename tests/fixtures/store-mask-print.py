#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Decompiled store masks (SPRUFE8B STH/STW/STDW): IMAGE CASES.json [be]. TI assembled, no firmware bytes."""
import importlib.util, json, os, subprocess, sys
from pathlib import Path

SLOT = 0x100
# name, B14 context, signature, body, expectations
CASES = [
    # Unproven record base: one masked word store, not four byte stores into the record.
    ("record_word", None, "void f(R *p)",
     [" ZERO.L1 A5", " STW.D1 A5,*+A4[2]", " B.S2 B3", " NOP 5"],
     {"stores": [[4, 0xfffffffc]]}),
    ("param_half", None, None,
     [" STH.D1T2 B4,*+A4[3]", " B.S2 B3", " NOP 5"],
     {"stores": [[2, 0xfffffffe]]}),
    ("param_dword", None, None,
     [" STDW.D1T2 B5:B4,*+A4[1]", " B.S2 B3", " NOP 5"],
     {"stores": [[8, 0xfffffff8]]}),
    # Known but misaligned DP, short and 15-bit forms: the constant address itself aligns down.
    ("dp_odd", 0x6BF1, None,
     [" STW.D2 B4,*+B14[10]", " STH.D2 B4,*+B14[30]", " STW.D2 B4,*+B14[40]", " STH.D2 B4,*+B14[100]",
      " B.S2 B3", " NOP 5"],
     {"stores": [], "ram": [[0x6C18, 4], [0x6C2C, 2], [0x6C90, 4], [0x6CB8, 2]], "no_mask": True}),
    # Provably aligned bases print without a mask.
    ("dp_aligned", 0x6BF0, None,
     [" STW.D2 B4,*+B14[10]", " STH.D2 B4,*+B14[30]", " STW.D2 B4,*+B14[40]", " STH.D2 B4,*+B14[100]",
      " B.S2 B3", " NOP 5"],
     {"stores": [], "ram": [[0x6C18, 4], [0x6C2C, 2], [0x6C90, 4], [0x6CB8, 2]], "no_mask": True}),
    ("sp_frame", None, None,
     [" ADDK.S2 -32,B15", " STW.D2 B3,*+B15[7]", " STDW.D2 B5:B4,*+B15[1]", " STW.D2 B4,*+B15[4]",
      " STH.D2 B4,*+B15[10]", " ADD.L1X B15,8,A4", " CALLP.S2 {tag}_callee,B3",
      " LDW.D2 *+B15[7],B3", " NOP 4", " B.S2 B3", " ADDK.S2 32,B15", " NOP 4",
      "{tag}_callee:", " B.S2 B3", " NOP 5"],
     {"stores": [], "stack": 3, "no_mask": True, "callee": True}),
]


def main():
    if len(sys.argv) not in (3, 4) or len(sys.argv) == 4 and sys.argv[3] != "be":
        raise SystemExit("Usage: store-mask-print.py IMAGE CASES.json [be]")
    image_path, manifest_path = map(Path, sys.argv[1:3])
    big = len(sys.argv) == 4
    spec = importlib.util.spec_from_file_location("continuation", Path(__file__).with_name("pipeline-caller-continuation.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    lines, rows = [], []
    for index, (name, b14, signature, body, expect) in enumerate(CASES):
        tag = "ct_store_mask_" + str(index)
        lines += [' .sect ".' + tag + '"', " .nocmp", tag + ":"] + [line.format(tag=tag) for line in body]
        rows.append(dict(name=name, tag=tag, entry=0x1000 + index * SLOT, b14=b14, signature=signature, **expect))
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
        row["size"] = len(raw) - (8 if row.get("callee") else 0)
        if row.get("callee"):
            row["callee"] = row["entry"] + len(raw) - 8  # B B3; NOP 5 closes the section
    image_path.write_bytes(image)
    manifest_path.write_text(json.dumps(rows, indent=2) + "\n")
    print("store-mask-print cases", len(rows))


if __name__ == "__main__":
    main()
