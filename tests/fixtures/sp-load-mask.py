#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Loads through B15 lift unmasked (SPRUFE8B LDW, SPRAB89 3.2): IMAGE CASES.json [be]. TI assembled, no firmware bytes."""
import importlib.util, json, os, subprocess, sys
from pathlib import Path

SLOT = 0x100
# name, compressible, body, (B15 loads, masked loads, decompile)
CASES = [
    # An argument saved at entry SP is read back by a loop that pops with LDW *++B15[2]; the store must survive.
    ("stack_store", False,
     [" STW.D2T1 A4,*B15--[2]", " || MV.L1X B4,A2",
      "{tag}_top:", " LDW.D2T1 *++B15[2],A4", " SUB.L1 A2,1,A2", " NOP 3", " [A2] B.S1 {tag}_top", " NOP 5",
      " B.S2 B3", " NOP 5"], (1, 0, True)),
    # Every 32-bit B15 load form, short and 15-bit, beside masked LDW controls through A4, A15, B4 and B14.
    ("sp_forms", False,
     [" LDW.D2T2 *+B15[1],B4", " LDW.D2T2 *-B15[1],B4", " LDW.D2T2 *+B15[B0],B4", " LDW.D2T2 *-B15[B0],B4",
      " LDW.D2T2 *--B15[1],B4", " LDW.D2T2 *++B15[1],B4", " LDW.D2T2 *B15--[1],B4", " LDW.D2T2 *B15++[1],B4",
      " LDW.D2T2 *--B15[B0],B4", " LDW.D2T2 *++B15[B0],B4", " LDW.D2T2 *B15--[B0],B4", " LDW.D2T2 *B15++[B0],B4",
      " LDW.D2T1 *+B15[40],A4", " LDH.D2T2 *+B15[3],B4", " LDHU.D2T2 *B15++[2],B4", " LDH.D2T2 *+B15[100],B4",
      " LDHU.D2T2 *+B15[100],B4", " LDB.D2T2 *+B15[3],B4", " LDBU.D2T2 *+B15[200],B4", " LDDW.D2T2 *++B15[1],B5:B4",
      " LDDW.D2T2 *+B15[1],B5:B4", " LDNW.D2T2 *+B15[1],B4", " LDNDW.D2T2 *+B15[1],B5:B4",
      " LDW.D1T1 *+A4[2],A5", " LDW.D1T1 *++A15[1],A5", " LDW.D2T2 *+B4[2],B5", " LDW.D2T2 *+B14[40],B5",
      " LDW.D2T2 *++B14[1],B5", " B.S2 B3", " NOP 5"], (23, 5, False)),
    # Compact Dstk and Dpp loads (SPRUFE8B C-16, C-21) beside 32-bit B15 loads in one header packet.
    ("sp_compact", True,
     [" LDW.D2T1 *+B15[5],A1", " LDW.D2T2 *++B15[2],B3", " LDDW.D2T2 *++B15[1],B5:B4", " LDW.D2T2 *B15++[1],B4",
      " LDH.D2T2 *+B15[3],B4", " NOP 4", " B.S2 B3", " NOP 5"], (5, 0, False)),
]


def main():
    if len(sys.argv) not in (3, 4) or len(sys.argv) == 4 and sys.argv[3] != "be":
        raise SystemExit("Usage: sp-load-mask.py IMAGE CASES.json [be]")
    image_path, manifest_path = map(Path, sys.argv[1:3])
    big = len(sys.argv) == 4
    spec = importlib.util.spec_from_file_location("continuation", Path(__file__).with_name("pipeline-caller-continuation.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    lines, rows = [], []
    for index, (name, compact, body, counts) in enumerate(CASES):
        tag = "ct_sp_load_" + str(index)
        lines += [' .sect ".' + tag + '"'] + ([] if compact else [" .nocmp"]) + [tag + ":"] + [line.format(tag=tag) for line in body]
        rows.append(dict(name=name, tag=tag, entry=0x1000 + index * SLOT, sp=counts[0], masked=counts[1], decompile=counts[2]))
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
        if big:  # a compact word's first slot is its 16 LSBs in either byte order (SPRUFE8B 3.10.2.3)
            raw = b"".join(raw[k:k + 4][::-1] for k in range(0, len(raw), 4))
        at = row["entry"] - 0x1000
        image[at:at + len(raw)] = raw
        row["size"] = len(raw)
    image_path.write_bytes(image)
    manifest_path.write_text(json.dumps(rows, indent=2) + "\n")
    print("sp-load-mask cases", len(rows))


if __name__ == "__main__":
    main()
