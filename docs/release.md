# v1.0.5 release preparation

This is an unreleased candidate following `v1.0.4`. Local changes are prepared for
review; no release tag or push is part of this preparation.

## Changes to review

- Native B/BNOP delay-window recovery and CALLP packet links preserve tail
  effects and reject unsafe windows.
- Explicit exact packet schedules capture parallel inputs, pending branches,
  delayed register/memory/status effects and normal software-loop timing.
  Closed call and caller-continuation traces require bounded, immutable plans.
- Compact operands, memory widths/address scaling and full32 encoding identity
  are corrected. `C6000EncodingInfo` exposes distinctions hidden by assembly
  spelling. Normal post-loop dispatch follows the SPKERNEL delay; buffered
  missed stalls are refused.
- The release runner checks the built archive in an isolated Ghidra copy in
  both endian modes. CI runs the core regressions and retains logs and results.

See [CHANGELOG.md](../CHANGELOG.md) for the detailed changes and TI references,
[verification](verification.md) for commands, and [limitations](limitations.md) for the
boundaries of the models.

## Compatibility and migration

| Item | Value |
|---|---|
| Planned repository tag | `v1.0.5` |
| Ghidra compatibility matrix | 12.1.3 / JDK 21; 12.1.4 / JDK 21; 12.2 / JDK 25 |
| Language version | 1.1 for all four variants |
| Archive naming | `ghidra_<Ghidra version>_PUBLIC_<build date>_C6000.zip` |
| `extension.properties` version | Ghidra compatibility version, substituted from `@extversion@` during build |

The extension-property version is **not** the repository release number. Keep the token;
setting it to `1.0.5` would break Ghidra's compatibility check. The language minor
version triggers native re-disassembly of existing programs. Keep a packed backup and
annotation inventory before migration; existing Bad Instruction bookmarks may be
removed. See [language prototype migration](internals.md#language-prototype-migration).

## Verification record

Verified locally on 2026-10-28 with `--with-ti --jobs 2`: 32 core fixture imports and
three TI-assembled fixture imports per endian, **70 per Ghidra version; 210 total, all
passed**. Native decompiler limits remain 15/30 seconds.

| Ghidra | JDK | LE / BE result |
|---|---|---|
| 12.1.3 | 21 | 35 / 35 passed |
| 12.1.4 | 21 | 35 / 35 passed |
| 12.2 | 25 | 35 / 35 passed |

Each report records the verified archive's SHA-256; a copy of that exact archive is
retained beside it so later builds cannot overwrite the evidence. These are worktree
verification snapshots, not published release assets. The seven release-tool unit tests,
shell syntax and local Markdown links/anchors also pass. CI is configured for the same
core matrix; this local preparation did not run a remote workflow.

To reproduce these checks, use the commands below and retain the generated
`summary.json`, logs and archive. Additional tests outside the runner's fixture registry
need their own results; a core-suite pass does not cover them.

## Checklist before tagging

- [ ] Review the candidate diff and approve the release scope.
- [x] Complete the core suite for each compatibility-matrix row, retaining its
  `summary.json` and logs; require all checks in both endian modes.
- [x] Complete `--with-ti` for predicate facts, caller continuations and
  post-loop dispatch. A missing TI assembler is a failed prerequisite.
- [ ] For target-specific changes, run the optional corpus/oracle checks on
  representative inputs and record the load base, window and tool versions.
- [ ] After approval, date the planned v1.0.5 changelog section and build from
  the final release commit. Retain the verified archive paths and SHA-256 hashes.
- [ ] Tag/push/publish only when explicitly authorized, attaching one archive
  per Ghidra version with matching release notes and checksums.

For local verification:

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
python3 tools/verify.py --jobs 2
python3 tools/verify.py --with-ti --jobs 2
```

To check an existing archive without installing it:

```sh
python3 tools/check_archive.py dist/ghidra_12.2_PUBLIC_YYYYMMDD_C6000.zip --ghidra-version 12.2
```

The build records the exact Gradle task output in `$GHIDRA_WORK/archive-path.txt`, and
verification records its SHA-256. Select that output rather than the newest zip from
another Ghidra version or run.
