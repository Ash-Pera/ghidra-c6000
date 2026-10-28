# Release guidance

Release `v1.1` adds exact packet schedules, normal software-loop timing,
source-bound caller traces, conservative execute-packet completion and decoder
repairs. See the [changelog](../CHANGELOG.md#11---2026-10-28) for the release
notes and [verification](verification.md) for the test workflow.

## Compatibility and migration

| Item | Value |
|---|---|
| Repository release | `v1.1` |
| Ghidra compatibility matrix | 12.1.3 / JDK 21; 12.1.4 / JDK 21; 12.2 / JDK 25 |
| Language version | 1.1 for all four variants |
| Archive naming | `ghidra_<Ghidra version>_PUBLIC_<build date>_C6000.zip` |
| Extension-property version | Ghidra compatibility version, substituted from `@extversion@` during build |

Keep the `extension.properties` version token. That field identifies the
compatible Ghidra version, rather than the repository release. Each release
archive must match the Ghidra installation used to build it.

The language minor version triggers native re-disassembly of existing programs.
Keep a packed backup and annotation inventory before upgrading; existing Bad
Instruction bookmarks may be removed. See
[language prototype migration](internals.md#language-prototype-migration).

## Release verification

Build from a clean release commit and run the suite for every matrix row:

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
python3 tools/verify.py --ghidra /path/to/ghidra --with-ti --jobs 2
```

The runner checks 43 core fixture imports and three TI-assembled fixture
imports per endian: 92 per Ghidra version, or 276 across the matrix. Native
decompiler checks retain their 15/30-second limits. CI runs the core suite
without the proprietary TI assembler.

Also run the focused checks for features outside the runner's registry:

| Feature | Fixture | Ghidra test |
|---|---|---|
| Strict caller/store tails | `caller-tail.py` | `C6000CallerTailTest.java` |
| Reviewed parallel-peer recovery | `parallel-peers.py` | `C6000ParallelPeersTest.java` |
| Ordinary execute-packet completion | `parallel-peers.py` | `C6000ParallelPeerAnalyzerTest.java` |

Run each on a fresh import in both endian modes. The complete release check
therefore adds six focused imports per matrix row. Contracts and invocation
arguments are documented in [caller-tail traces](caller-tail-traces.md),
[reviewed peer recovery](recover-parallel-peers.md) and
[execute-packet completion](execute-packet-recovery.md).

Retain each `summary.json`, logs and the exact tested archive. Reports record
the commit and archive SHA-256. If source changes after verification, repeat
the affected checks and build release assets from the final commit.

## Checklist before tagging

- Confirm the release scope, date its changelog entry and commit the changes.
- Complete the unit tests, full compatibility matrix and focused checks above.
- For target-specific changes, run the optional corpus/oracle checks on
  representative inputs and record the load base, window and tool versions.
- Require a clean working tree and passing CI for the release commit.
- Retain the verified archive for each Ghidra version and generate `SHA256SUMS`.
- Create the annotated release tag at that same commit and push it with the
  release branch.
- Publish the GitHub release with the three matching archives, checksums,
  upgrade notes and links to the changelog and verification results.

## Checking release assets

To validate an archive without installing it:

```sh
python3 tools/check_archive.py dist/ghidra_12.2_PUBLIC_YYYYMMDD_C6000.zip --ghidra-version 12.2
```

The build records its exact Gradle task output in
`$GHIDRA_WORK/archive-path.txt`; verification preserves a copy and records its
SHA-256. Select that output rather than another zip left in `dist/`. Check
the uploaded asset names, sizes and SHA-256 digests against the local files
before considering publication complete.
