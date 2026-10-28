<!-- SPDX-License-Identifier: Apache-2.0 -->
# Recover physically parallel peers

`C6000RecoverParallelPeers.java` is an opt-in script for a stale listing that omits
instructions physically parallel with an existing instruction. Its default mode writes a
report and checks that the program modification number stays unchanged. It does not run
autoanalysis, clear code/data, write decode context, expand function bodies, or follow
fall-through/branch flow.

The proof is the physical p-bit chain described in TI SPRUFE8B sections 3.5 and
3.10.2/3.10.4. This establishes membership of the same execute packet; it does not prove
a complete branch-delay window or an alternate entry. Existing delay-window refusal
remains valid independently. Fetch headers are skipped, not defined by this script.

The manifest and report paths must differ after absolute-path normalization; the script
refuses identical paths before any read/write of the report.

## Manifest

Create a JSON manifest with unsigned decimal addresses (hexadecimal JSON numbers are
invalid):

```json
{
  "schema": 1,
  "language_id": "C6000:LE:32:default",
  "source": {
    "start": 4096,
    "length": 32,
    "sha256": "SHA256_OF_THE_EXACT_32_SOURCE_BYTES"
  },
  "anchors": [
    {"address": 4096, "allowed_end": 4104, "expected_bytes": "EXACT_ANCHOR_HEX"}
  ]
}
```

The source must cover whole 32-byte fetch packets, contain every reviewed
instruction/header, and be at most 16 MiB. An anchor must be a defined instruction whose
complete bytes match `expected_bytes`. `allowed_end` is an exclusive limit no more than
64 bytes beyond its anchor. Keep the reviewed extent limited to the packet peers being
recovered. The language, full source SHA, anchor bytes, physical widths/header fields,
packet length and complete candidate extents are checked.

## Review and apply

Run the script with `MANIFEST REPORT` to inspect candidates and unresolved reasons.
Review the complete report, then hash its exact bytes and explicitly run
`MANIFEST REPORT apply REVIEW_SHA256`. Apply re-plans against the current database and
requires identical manifest and candidate-plan hashes. It archives the reviewed report
before replacing the report path with an apply receipt. A wrong review/source hash or
changed plan fails without inserting instructions.

Each candidate must be entirely free of existing instruction/data units, including an
overlap beginning inside the candidate. Ownership must be uniform and either unowned or
equal to the anchor's owner; foreign bodies, function entries and partial-body extents
are refused. Existing defined instructions may bridge a chain without being changed only
when ownership is uniform across their complete extent and is unowned or the anchor
owner. Stored-context and physically seeded fresh parses must agree in width, text and
canonical native p-code. Opaque/unsupported semantics, invalid p-code branches, and new
control-transfer peers are refused. Stale context is reported, never repaired.
Eight-instruction header-based packets and oversized packets are refused.

Apply requires idle analysis and uses an analysis worker with analyzer changes
suppressed. It inserts only reviewed instruction units with `Listing.createInstruction`;
immediately verifies their native width/text/p-code and unchanged context; and rolls
back if existing instruction metadata, comments, function names/bodies/prototypes or
references drift. It preserves existing labels without relabeling; the fixture checks an
undefined-address user label. New normal instruction references may be added. Use a
program backup and a complete annotation audit when applying to an annotated database,
as the fixture audit does not inventory every possible third-party property.

Existing defined pointer/data units are always conflicts, even when their bytes
plausibly encode an instruction. Reclassifying incorrectly created data needs a
separate, explicitly reviewed plan. Uniform fill, decodable-only bytes, headers without
a code anchor and unrelated gaps are outside this script's proof.

## Focused qualification

The synthetic fixture `tests/fixtures/parallel-peers.py` invokes TI cl6x for full32
opcodes and generates documented compact NOP/header fields.
`C6000ParallelPeersTest.java` qualifies report/apply behavior in isolated LE and BE
programs with no autoanalysis. Each run covers 20 cases, creates six instruction units,
and verifies zero newly eligible candidates on repeat discovery. Cases include full32
branch peers, compact peers, cross-fetch/header chains, a nested-transfer delay-window
refusal with an accepted immediate peer, p=0, existing code/data at the first/suffix
byte, foreign/partial ownership, stale context, opaque/invalid semantics, reviewed-bound
cuts, oversized/header-based packets, and annotation/reference retention. An existing
defined peer whose body ends inside its instruction cannot bridge to a new candidate.
Identical normalized manifest/report paths fail with unchanged file bytes and program
modification number. Wrong source/review hashes and changed context plans fail without
modification.

These tests cover the script's bounded listing changes and refusal behavior. When
applying a report to another program, review its source bytes and candidate extents,
retain a backup, and check the annotations and properties that matter for that database.
The fixture's annotation inventory does not cover every third-party property.
