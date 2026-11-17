#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Apply each known-bad load-deferral mutant, run the native-load-latency fixture (LE and BE), restore; exit 1 if one survives."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SCHEDULER = ROOT / "src/main/java/c6000/C6000NativeLoadLatencyScheduler.java"
LANDING = "timeline.get(landing).cycle() < cycle + LOAD_LATENCY) landing++;"
# name, file, anchor (must occur once), replacement
MUTANTS = [
    ("drop the branch-in-window refusal", SCHEDULER,
     'return "a branch or call issues inside the load window";', "continue;"),
    ("commit one cycle early", SCHEDULER, LANDING, LANDING.replace("LOAD_LATENCY)", "LOAD_LATENCY - 1)")),
    ("commit one cycle late", SCHEDULER, LANDING, LANDING.replace("LOAD_LATENCY)", "LOAD_LATENCY + 1)")),
    ("ignore predication", SCHEDULER, "if (!inputs.contains(written)) continue;",
     "if (!inputs.contains(written) || written.equals(load.predicate())) continue;"),
]


def run_fixture(log):
    command = [sys.executable, ROOT / "tools/verify.py", "--with-ti", "--only", "native-load-latency", "--jobs", "2"]
    with log.open("w") as output:
        code = subprocess.run(list(map(str, command)), cwd=ROOT, stdout=output, stderr=subprocess.STDOUT).returncode
    text = log.read_text()
    match = re.search(r"(?:VERIFIED|FAILED): (\S+summary\.json)", text)
    if not match:
        raise RuntimeError(f"verify produced no summary; see {log}")
    failed = {}
    for record in json.loads(Path(match.group(1)).read_text())["results"]:
        headless = Path(record["log"])
        cases = re.findall(r"NATIVE_LOAD_LATENCY_CASE (\S+) FAIL", headless.read_text()) if headless.exists() else []
        if not record["passed"] and not cases:
            raise RuntimeError(f"{record['endian']} failed before any case ran (build or setup); see {headless}")
        failed[record["endian"]] = cases
    return code, failed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-control", action="store_true", help="do not first run the unmutated fixture")
    args = parser.parse_args()
    logs = ROOT / "scratch/mutants"
    logs.mkdir(parents=True, exist_ok=True)
    if not args.skip_control:
        code, failed = run_fixture(logs / "control.log")
        if code or any(failed.values()):
            raise SystemExit(f"control run failed {failed}; mutants prove nothing")
        print("control: unmutated fixture passes in LE and BE")
    survivors = 0
    for index, (name, path, anchor, replacement) in enumerate(MUTANTS):
        original = path.read_text()
        if original.count(anchor) != 1:
            raise SystemExit(f"mutant '{name}': anchor found {original.count(anchor)} times")
        try:
            path.write_text(original.replace(anchor, replacement))
            code, failed = run_fixture(logs / f"mutant{index}.log")
        finally:
            path.write_text(original)
        caught = code != 0 and all(failed.get(endian) for endian in ("le", "be"))
        survivors += not caught
        print(f"{'CAUGHT' if caught else 'SURVIVED'}: {name}: " +
              "; ".join(f"{endian} fails {', '.join(cases) or 'nothing'}" for endian, cases in sorted(failed.items())))
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main())
