#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Apply each mutant, run the overwritten-arm-predicate fixture, restore; every mutant must be caught.

Usage: mutate_overwritten_arm_predicate.py [--endian le|be] [NAME ...]
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
ANALYZER = ROOT / "src/main/java/c6000/C6000CallAnalyzer.java"
DELAY_SLOTS = ROOT / "src/main/java/c6000/C6000DelaySlots.java"
VERIFY = ROOT / "tools/verify.py"
LAST_WRITE = "\t\t\t\tvalue = decides ? write.value() : null;\n"

# name, file, unique anchor, replacement, failure the fixture must report
MUTANTS = (
    ("drop-last-write-override", ANALYZER, LAST_WRITE,
     "\t\t\t\tif (!decides || write.value() == null) return false;\n\t\t\t\tvalue = write.value();\n",
     "wrong nested return effects"),
    ("accept-any-later-write", ANALYZER, LAST_WRITE,
     "\t\t\t\tif (decides && write.value() != null) value = write.value();\n",
     "bad nested carry applied: bad_later_write"),
    ("tolerate-any-window-jump", DELAY_SLOTS,
     "!next.getAddress().equals(tolerate)&&(next.getFlowType().isJump()",
     "tolerate==null&&(next.getFlowType().isJump()",
     "bad nested carry applied: bad_extra_jump"),
    ("skip-first-in-packet", ANALYZER,
     "if (!C6000ExecutionPackets.issuePrefix(program, carrier.getAddress()).isEmpty()) return false;",
     "C6000ExecutionPackets.issuePrefix(program, carrier.getAddress());",
     "bad nested carry applied: bad_first_packet"),
    ("unimplied-guard-runs", ANALYZER,
     "\t\t\tif (guard == null) return true;\n\t\t\tif (!guard.replace",
     "\t\t\tif (guard != null) return true;\n\t\t\tif (!guard.replace",
     "bad nested carry applied: bad_unimplied"),
    ("check-carrier-only", ANALYZER,
     "for (int i = carrierIndex; i < path.size(); i++) {",
     "for (int i = carrierIndex; i <= carrierIndex; i++) {",
     "bad nested carry applied: bad_non_nop_tail"),
    ("peer-may-write-link", ANALYZER,
     "\t\t\t\t!noWritesDuring(path, issue, issue[branchIndex], issue[lastIndex], link)) return null;",
     "\t\t\t\tfalse) return null;",
     "bad nested carry applied: bad_peer_link"),
)


def run_mutant(name, target, before, after, expected, endian):
    original = target.read_text()
    if original.count(before) != 1:
        raise RuntimeError(f"mutation anchor for {name} is not unique")
    target.write_text(original.replace(before, after, 1))
    work = None
    try:
        result = subprocess.run(
            [sys.executable, str(VERIFY), "--with-ti", "--only", "overwritten-arm-predicate", "--endian", endian],
            cwd=ROOT, env=os.environ.copy(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        artifact = re.search(r"Verification artifacts: (.+)", result.stdout)
        if artifact is None:
            raise RuntimeError(f"verify.py produced no artifact path for {name}:\n{result.stdout}")
        work = Path(artifact.group(1).strip())
        summary_path = work / "summary.json"
        if not summary_path.is_file():
            raise RuntimeError(f"mutant did not build or reach the fixture: {name}\n{result.stdout[-4000:]}")
        failed = [item for item in json.loads(summary_path.read_text()).get("results", [])
                  if item.get("fixture") == "overwritten-arm-predicate" and not item.get("passed")]
        if result.returncode == 0 or len(failed) != 1:
            raise RuntimeError(f"mutant survived: {name}\n{result.stdout[-4000:]}")
        log_path = Path(failed[0]["log"])
        log = log_path.read_text() if log_path.is_file() else ""
        if expected not in log:
            raise RuntimeError(f"mutant failed for another reason: {name}\n{log[-4000:]}")
        print(f"MUTANT_CAUGHT {name}: {expected}", flush=True)
    finally:
        target.write_text(original)
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endian", choices=("le", "be"), default="le")
    parser.add_argument("names", nargs="*")
    args = parser.parse_args()
    env = os.environ
    env.setdefault("TI_C6000_BIN", str(Path.home() / "ti/ti-cgt-c6000_8.3.15/bin"))
    if not (Path(env["TI_C6000_BIN"]) / "cl6x").is_file():
        raise SystemExit("TI_C6000_BIN must point to a TI C6000 compiler directory")
    unknown = set(args.names) - {m[0] for m in MUTANTS}
    if unknown:
        raise SystemExit("unknown mutants: " + ", ".join(sorted(unknown)))
    for mutant in MUTANTS:
        if not args.names or mutant[0] in args.names:
            run_mutant(*mutant, args.endian)
    print("ALL_MUTANTS_CAUGHT", flush=True)


if __name__ == "__main__":
    main()
