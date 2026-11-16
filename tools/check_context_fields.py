#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail on overlapping contextreg fields, or one past the register, in the LE and BE define context blocks (docs/internals.md)."""
import argparse
from pathlib import Path
import re
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / "data/languages/c6000.sinc"
FIELD = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)")
SIZE = re.compile(r"define\s+register\s+offset=\S+\s+size=(\d+)\s*\[\s*contextreg\s*\]")
CARRIER = "c_h16"


def lines_for(path, endian, depth=0):
    """Source lines of the active branch for one endianness, includes expanded."""
    active = [True]
    for number, line in enumerate(path.read_text().splitlines(), 1):
        directive = line.strip()
        if directive.startswith("@if"):
            match = re.fullmatch(r'@if\s+ENDIAN\s*==\s*"(big|little)"', directive)
            if not match:
                raise ValueError(f"{path}:{number}: unsupported condition {directive}")
            active.append(active[-1] and match.group(1) == endian)
        elif directive == "@else":
            active[-1] = not active[-1] and active[-2]
        elif directive == "@endif":
            active.pop()
        elif not active[-1]:
            continue
        elif directive.startswith("@include"):
            yield from lines_for(path.parent / directive.split('"')[1], endian, depth + 1)
        else:
            yield path, number, line, depth


def fields(sinc, endian):
    size = None
    result = []
    inside = False
    for path, number, line, depth in lines_for(sinc, endian):
        code = line.split("#", 1)[0]
        if size is None and SIZE.search(code):
            size = int(SIZE.search(code).group(1)) * 8
        if not inside:
            inside = re.match(r"\s*define\s+context\s+contextreg\b", code) is not None
            continue
        if code.strip() == ";":
            break
        match = FIELD.match(code)
        if match:
            result.append((match.group(1), int(match.group(2)), int(match.group(3)),
                           f"{path.name}:{number}", depth > 0))
    if size is None or not result:
        raise ValueError(f"{sinc}: no contextreg size or define context block")
    return size, result


def problems(sinc):
    found = []
    for endian, label in (("little", "LE"), ("big", "BE")):
        size, declared = fields(sinc, endian)
        carriers = [f for f in declared if f[0] == CARRIER and f[4]]

        def viewed(first, last, included):
            return included and any(c[1] <= first and last <= c[2] for c in carriers)

        names = set()
        for index, (name, first, last, where, included) in enumerate(declared):
            if name in names:
                found.append(f"{label}: {name} declared twice ({where})")
            names.add(name)
            if last < first or last >= size:
                found.append(f"{label}: {name} ({first},{last}) lies past the {size}-bit contextreg ({where})")
            for other, ofirst, olast, owhere, oincluded in declared[:index]:
                if first > olast or ofirst > last:
                    continue
                # A compact view may alias its carrier and the other views, nothing else.
                if viewed(first, last, included) and viewed(ofirst, olast, oincluded):
                    continue
                found.append(f"{label}: {name} ({first},{last}) at {where} overlaps "
                             f"{other} ({ofirst},{olast}) at {owhere}")
    return found


def selftest(sinc):
    text = sinc.read_text()
    anchor = "  c_load_mode = (90,91) noflow"
    if text.count(anchor) != 2:
        raise SystemExit("selftest anchor missing: " + anchor)
    broken = {
        "LE overlap": (sinc.name, text[:text.rindex(anchor)] + "  c_load_mode = (89,90) noflow" +
                       text[text.rindex(anchor) + len(anchor):]),
        "BE overlap": (sinc.name, text.replace(anchor, "  c_load_mode = (89,90) noflow", 1)),
        "past size": (sinc.name, text.replace(anchor, "  c_load_mode = (95,96) noflow")),
        "view escapes its carrier": ("c6000_compact_context.sinc",
            (sinc.parent / "c6000_compact_context.sinc").read_text().replace("q_t=(35,35)", "q_t=(48,48)")),
    }
    with tempfile.TemporaryDirectory() as scratch:
        for label, (name, mutated) in broken.items():
            copy = Path(scratch) / label.replace(" ", "-")
            shutil.copytree(sinc.parent, copy)
            (copy / name).write_text(mutated)
            found = problems(copy / sinc.name)
            if not found:
                raise SystemExit(f"SELFTEST FAILED: the {label} copy passed")
            print(f"selftest {label}: caught: {found[0]}")
    print("C6000 context check selftest OK")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sinc", nargs="?", type=Path, default=DEFAULT)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        selftest(args.sinc)
    found = problems(args.sinc)
    if found:
        print("\n".join(found), file=sys.stderr)
        return 1
    for endian in ("little", "big"):
        size, declared = fields(args.sinc, endian)
        print(f"C6000 context fields OK: {endian}-endian, {len(declared)} fields in {size} bits")
    return 0


if __name__ == "__main__":
    sys.exit(main())
