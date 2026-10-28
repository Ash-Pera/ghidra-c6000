# Internals

How the module models the parts of the C6000 that do not map directly onto
SLEIGH: compact fetch packets, execute packets, delay slots and branch
targets, plus the ABI, the analysis language variants and the source layout.

## Languages

| Language | Use |
|---|---|
| `C6000:LE:32:default` | little-endian C674x / C64x+ / C64x / C67x+ / C67x |
| `C6000:BE:32:default` | big-endian variant (C6000 supports both byte orders) |
| `C6000:LE:32:analysis`, `C6000:BE:32:analysis` | same decode, simplified single-precision p-code for reading float-heavy code (see [below](#floating-point-decompilation)) |

An ELF loader opinion maps `EM_TI_C6000` (e_machine 140) to
`C6000:LE:32:default`, so a little-endian C6000 ELF picks it automatically.
The opinion only matches little-endian files; for a big-endian ELF or a raw
binary, choose the language and (for raw images) the base address yourself.

C674x is the union of the C64x+ and C67x+ instruction sets (SPRUFE8B §1.1), so
one description serves the older parts, which are subsets.

## Compact 16-bit fetch packets

This is the part of C6000 that naive decoders get wrong, so it is worth
describing the model.

A fetch packet is eight 32-bit words (32 bytes). It is a **compact** packet
exactly when bits 31–28 of its eighth word are `1110`; that word is then a
*header* rather than an instruction, its layout field says which of the other
words hold two 16-bit instructions, and its expansion field supplies the
register set (`RS`), LD/ST data size (`DSZ`), saturation (`SAT`) and
branch-mode (`BR`) parameters that a 16-bit opcode cannot express (§3.10.2).

The header sits **after** the instructions it describes. SLEIGH fixes an
instruction's length from the tokens it matches, so a constructor that peeked
at word 7 would have to declare every compact instruction 32 bytes long. The
decode context is therefore primed out of band:

* `c6000.C6000PacketAnalyzer` runs before Ghidra's disassembly pass and writes
  the per-slot context (`c_is16`, `c_isheader`, `c_rs`, `c_dsz`, `c_sat`, `c_br`, `c_prot`, `c_pfollow`)
  for every compact packet.
* `c6000.C6000PacketContext.prime(program, monitor)` is the same logic as a
  static helper, so scripts and headless runs can call it directly; the corpus
  test does exactly that.
* With no context primed, every word decodes as a normal 32-bit instruction — a
  graceful fallback rather than a hard failure.

Only the eighth word of a compact fetch packet decodes as a 4-byte `CPKT`
instruction. The `1110` prefix in bits 31..28 is the reserved predication
encoding `creg=7, z=0` (Table 3-9), so no valid 32-bit instruction matches it.

## Execute packets, delay slots and parallel semantics

* Bit 0 of each 32-bit opcode is its p-bit. A compact 16-bit instruction's
  p-bit comes from bits 13–0 of its fetch-packet header. In either case,
  `p=1` chains the next instruction into the same execute packet, including
  across a fetch-packet boundary.
* Ordinary instructions are still lifted individually. Reads of a register
  overwritten by another instruction in the same packet can see the new value
  too early; instruction-result latencies are not scheduled by this p-code.
* `C6000DelaySlots` proves finite unconditional `B`/`BNOP` windows after code
  discovery, including IRP/NRP forms. It counts execute cycles, BNOP's implied
  NOPs, NOP/ADDKPC multi-cycle counts, protected loads and crossed compact headers, then records
  the physical byte count in `c_flow_delay`. `tools/gen_flow_delay.py` generates
  the constant `delayslot(n)` choices: SLEIGH counts bytes, not instructions.
  Targets and predicates are sampled before delay work. Native parsing is
  checked before code units change; recovery is transactional and retains
  comments, symbols, reference metadata and explicit fallthrough overrides.
* Nested transfers, defined data and another function's entry/ownership prevent
  recovery. Predicated full windows, BDEC/BPOS, ordinary result latency and
  overlapping branch pipelines still need modeling. Existing delayed-call
  `CALL` overrides keep their established conservative treatment.
* CALLP supplies its own five implied NOP cycles. Its parallel companions
  execute before the side-specific A3/B3 link is written; `inst_next` after
  native packet expansion is the return address. Ghidra's generic Java
  delay-depth/fallthrough counter parses all followers with the branch's
  compact context. The late pass uses native delay-byte counts and corrects
  CALLP fallthrough from the proved window. Mixed-width instruction stepping
  in the stock emulator remains limited; listing p-code and decompilation
  use address-specific contexts and are checked separately.
* Branch targets are **PCE1-relative** — relative to the first instruction of
  the containing fetch packet, not to the branch itself. `B`/`CALLP`/`BNOP`/
  `BDEC`/`BPOS`/`ADDKPC` all use `inst_start & 0xFFFFFFE0`, exactly as the
  manual's Execution blocks specify. A 32-bit `BNOP` displacement counts
  words in an ordinary fetch packet but halfwords in a header-based (compact)
  one, so it can reach 16-bit instructions; the `c_hdrpkt` context bit, primed
  with the rest of the packet context, selects the scale. Direct branch and
  call targets export in RAM, so Ghidra's flow references and disassembler
  follow the code address.
  The delayed-call analyzer treats a `B` (immediate or register) as a call
  when its five delay cycles write `B3` with `ADDKPC` or with an `MVK`/`MVKH`
  pair (the `MVK` may precede the branch) to a return address just past the
  delay window. It decodes the delay slots itself when Ghidra has not, gives
  the branch a CALL flow override and a fall-through into its delay slots,
  adds a call reference for a register target loaded by `MVK`/`MVKH` in the
  preceding straight-line code, and recomputes the caller's body. That
  look-back decodes forward from about 40 words earlier, so constants in the
  undecoded delay slots of an earlier jump (or in code words that analysis
  typed as pointers) still count; it follows `MV` and `ADD`/`OR` of zero,
  skips instructions predicated opposite to the branch, and ignores the
  p-code a compact branch borrows from its parallel followers. A register
  call recognised before its constants were decoded is revisited when code
  just before it appears. Predicated
  calls stay conditional; `B B3` stays a return. The TI compiler's if/else
  call pairs are recognised: a branch inside the window is allowed when its
  predicate is the exact opposite of the call's, `B3` may be set before the
  branch, and reaching the return address `B3` already holds ends the window
  (compact packets can skew the cycle count). In such a pair only one arm is
  a call ("call Y if p, else jump to X"): a register arm is the call, and
  between two immediate arms the one with the nearer target (the local
  else-block) stays a conditional jump; arms to the same target both stay
  calls. It also reclaims
  `CALL_RETURN` tail calls that Ghidra guessed before the delay slots were
  understood, but never one whose callee is marked no-return or whose call
  form is terminal, since another analyzer would flip it back and the two
  would loop. The processor spec disables Ghidra's heuristic
  "Non-Returning Functions - Discovered" analyzer (`enableNoReturnAnalysis`):
  it walks the static fall-through after each call, which on C6000 is
  undecoded until the call is recognised, so it marked returning functions
  no-return and then cleared the code that disproved it. The name-based
  "Known" analyzer still runs. A separate
  early analyzer classifies branches through the ABI return register `B3` as
  returns before Ghidra's switch analysis. Unpredicated `B`/`BNOP` register
  branches retain conservative fall-through during code discovery; an analyzer
  redecodes them as terminal branches or returns before Decompiler Switch
  Analysis so the decompiler sees their actual control flow.

* Switch tables. The TI compiler dispatches a switch with a guard
  (`CMPLTU K,idx` or `CMPGTU idx,K`, `K` an immediate or a constant
  register), an `MVK`/`MVKH` table base, the scaled index added in, a
  predicated `LDW` of the entry and `B`/`BNOP` through it, with the
  out-of-range branch in the delay slots. Ghidra's decompiler finds such a
  table but cannot bound it through the predicated delay-slot code ("Too
  many branches"). `C6000JumpTableAnalyzer` recognises the idiom with the
  delayed-call analyzer's look-back, reads the `K+1` entries (stopping early
  at a word that is not an even address in the dispatching block; with no
  guard it recovers nothing), adds them as computed-jump references, decodes
  them and writes a jump-table override so the decompiler emits the
  `switch`. It runs for each new function, so a function a script creates
  later still gets its override, and the late branch pass decodes the cases
  of newly found code. It never rewrites an existing override or refixes an
  unchanged body; doing so retriggered function analysis without end.

The `jump-table.py` fixture and `C6000JumpTableTest.java` check, in both
endian modes, that a guarded three-case dispatch gets exactly its three
targets although a fourth valid code address follows the table, and that the
decompiler emits the `switch`.

The `branch-flow.py` fixture and `C6000FlowTargetTest.java` check eight direct
branch/call forms in both endian modes, including conditional versus
unconditional flow types and a `BNOP` in a header-based packet. The
`delayed-call.py` fixture and `C6000DelayedCallTest.java` check, after
auto-analysis in both endian modes, an `ADDKPC` immediate call and an
`MVK`/`MVKH` register call, an if/else pair of predicated calls with `B3`
set before the first arm, and a call-or-jump pair whose near arm must stay a
jump: all calls fall through into their delay slots, keep
the code after the return point in the caller, and make the callee a
function. Ten stage 2 firmware branch/call sites, including
compact forms, also passed the RAM flow check. On a fresh stage 1 raw import
with entry `0x11801da0`, auto-analysis found functions at `0x11804280`,
`0x118048a0`, and `0x11804360`, with zero `const:` flow-error bookmarks. A raw
binary needs an entry point; `C6000SetEntry.java` supplies it in the GUI and
headless tests. The packet-context analyzer runs before Ghidra's entry-point
disassembler so compact target slots get their width context in time. A fresh
stage 2 import also created a function at the checked `CALLP` target
`0xc0012720`. The return-flow regression checks 480 stage 2 `B3` branches,
including 31 predicated returns that retain their fall-through edge; no
unpredicated return retains a fall-through edge. A late branch analyzer
revisits code discovered during switch analysis; without it, three `BNOP B3`
returns were left as computed jumps.

Ghidra's generic Basic Constant Reference Analyzer can exhaust the heap while
exploring the stage 2 control-flow graph. The C6000-specific analyzer bounds
each propagation walk to 512 bytes, still recovering nearby register-built
targets. A fresh stage 2 raw import with the default analyzers recovered 144
functions with zero `const:` flow-error bookmarks; a 60-second-per-function
audit decompiled all 144. Three remaining Error bookmarks are one branch
into `0xffffffff` fill and two odd-address disassembly attempts, not failures
to decode aligned firmware code. In a separate full-payload sweep followed by
autoanalysis, Decompiler Switch Analysis took about 53 seconds and Stack took
about 4 seconds. The reported `0xc001dd80` merger did not recur.

### Floating-point decompilation

`C6000UseAnalysisLanguage.java` switches a comparison copy to the matching
endian `analysis` language without running auto-analysis. Keep the original
default-language program: the concise language deliberately approximates
floating-point status and special rounding. Changing the language is a
reading aid, not a fix to the exact floating-point model.

The default `C6000:LE:32:default` and `C6000:BE:32:default` languages retain
the detailed floating-point rounding and status-register model. Its SP
add/subtract, multiply and DP-to-SP rounding helpers use mask selections
instead of internal p-code branches. All four rounding modes, signed zeros,
NaNs, denormal handling, sticky status bits and the lost-small-addend
correction remain explicit; no opaque arithmetic userop is introduced.
This keeps repeated instructions from multiplying the decompiler block graph.
The inputs are captured before the destination is written, including aliases.
Pure speculative p-code arithmetic on special values is discarded before
architectural results or flags are selected (SPRUFE8B sections 2.10.1, 2.10.3
and 3.12 ADDSP/SUBSP/MPYSP/DPSP execution descriptions).

For reading
float-heavy functions, explicitly select `C6000:LE:32:analysis` or
`C6000:BE:32:analysis` when importing a program. This variant uses native
single-precision p-code for `INTSP`, `INTSPU`, `MPYSP`, `ADDSP`, `SUBSP`, and
the SP comparisons. It represents status-register effects with the opaque
`c6000_fp_status` userop, so its flag values and special rounding cases are
not suitable for emulation. The same stage 2 function at `0xc0008c44`
decompiled to 36 lines with the analysis language versus 219 with the exact
language; the `fVar1 < 1.0` branch was visible in the shorter output.

## Switch override ownership

Ghidra stores switch metadata as
`function::override::jmp_<branch>::switch` and `case_<n>` labels. A body repair
can leave those labels under the former function. Passing the detached
override to the native decompiler can crash it even when the instruction
listing is valid.

The jump-table and register-branch passes now verify ownership. Repair is
limited to canonical metadata whose ordered cases match the table recovered
from the instructions and bytes. A table moves to its current function owner;
if no owner exists or that owner already has a table, its namespace moves
under `C6000_detached_switches`. Existing label IDs, names and addresses stay
intact. Unverified manual case choices stay unchanged. The standalone
`C6000RepairSwitchOverrides.java` script applies the same repair to a legacy
comparison copy.

## Calling convention

`data/languages/c6000.cspec` implements the C6000 C ABI:

| | |
|---|---|
| arguments | A4, B4, A6, B6, A8, B8, A10, B10, A12, B12, then the stack |
| 32-bit return | A4 |
| return address | B3 |
| stack pointer | B15 |
| frame pointer | A15 |
| data pointer | B14 |
| callee-saved | A10–A15, B10–B15 |

## Function ID

`tools/gen_fid.py` builds a Function ID database from a TI run-time library.
The **`.fidbf` is deliberately not shipped**: the TI code generation tools'
licence does not clearly permit redistributing a database derived from TI's RTS,
and the safe default is to ship the generator and let each user build it from
their own CGT install. Read the script's header before redistributing anything
it produces.

## Repository layout

```
build.gradle, settings.gradle, extension.properties, Module.manifest
data/languages/          c6000.sinc (framework), c6000_decode.sinc (generated),
                         c6000_manual.sinc, c6000_compact.sinc, c6000_memory.sinc,
                         c6000_nonalign.sinc (generated), c6000_semantics.sinc,
                         c6000_placeholders.sinc (generated), c6000_{le,be}[_analysis].slaspec,
                         ldefs/pspec/cspec/opinion
ghidra_scripts/          C6000*Test.java checks (one per fixture family), C6000CorpusTest.java,
                         C6000LoopReplay.java, analysis/decompiler audits
src/main/java/c6000/     packet context, packet/call/return/register-branch/software-loop
                         analyzers, software-loop model (C6000SoftwareLoops, C6000LoopBuffer)
tests/fixtures/          generators for the fixture images and expected-result tables
docs/                    verification, internals, limitations, software-loop conformance notes
tools/                   build.sh, generators (gen_*.py, build_encodings.py, parse_encodings.py),
                         GNU-oracle comparison and audit scripts
.github/                 workflows/build.yml, issue templates
```

`c6000_decode.sinc` and `c6000_placeholders.sinc` are generated by
`tools/gen_decode.py` from an encoding table parsed out of SPRUFE8B §3.12
(`tools/build_encodings.py`); `c6000_memory.sinc` and `c6000_nonalign.sinc`
come from `tools/gen_memory.py` and `tools/gen_nonalign.py`. They are committed so the extension builds without the
manual; edit their generators rather than the generated files.

## Lossless full32 encoding identity

SPRUFE8B section 3.12's scalar `MV` opcode maps cover distinct ADD-zero and
OR-zero encodings. The full32 decoder displays the actual primitive and an
explicit zero operand; cross-path variants of these constructors include X
in the unit suffix. This is a display change: their existing move p-code is
retained. The separate 40-bit register-pair move keeps its MV spelling, and
an equal-source SUB is not collapsed into an assembler-chosen ZERO alias.

TI-compatible text alone still cannot select every address form. In particular,
small B14/B15 offsets may use short5 or long15 forms with identical spelling.
The public `C6000EncodingInfo.describe(Instruction)` utility returns that form,
encoded element offset and scale, short-memory addressing mode, base/offset
registers, predicate and p fields, known scalar-move cross paths,
and numeric packet layout/expansion/p bits. `C6000ExportEncodingInfo.java
<output.jsonl> [start end]` exports these alongside ordinary listing text.
It does not invent a TI suffix or emit raw opcode directives.

The packet description distinguishes unavailable header bytes from a known
ordinary packet. A full32 BNOP's displacement scale is two bytes in a
header-based packet and four in an ordinary packet; B, BDEC and BPOS remain
four-byte scaled. An unknown BNOP context has a null scale. These rules are
from SPRUFE8B 3.10.2 and the section 3.12 opcode/execution descriptions;
address-form fields follow 3.9.3 and the ADDAW/scalar load/store opcode maps.
Compact-specific form details are intentionally left to their compact decoder.

`C6000EncodingInfo.registerCopySource(Instruction)` identifies conservative,
unconditional MV or integer ADD/OR-zero copies with zero in either operand
position. Constant-call recovery uses it so `ADD.Dx src,0,dst` retains the
same known register value as its former MV spelling. Unknown cross-path
metadata is null; the API does not assume every bit 12 is a cross selector.

### Language prototype migration

The 1.1 language minor version forces Ghidra's native re-disassembly upgrade.
This is necessary when a corrected compact operand partition distinguishes bits
that an older shared persisted prototype ignored. Updating the extension alone
can leave old programs with stale operand text and p-code. Preserve a packed
backup and annotation inventory before upgrade. Native migration can remove
historical Bad Instruction error bookmarks; retain/restore those from the
backup if preserving every annotation is required. Audit actual processor
context and instruction extents as well as symbols, functions and references.
