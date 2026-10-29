# Exact packet schedules (explicit opt-in)

C6000 execute packets read their inputs before parallel writes become visible. A branch
can issue before an earlier branch lands. The second branch remains pending when the
first transfer redirects instruction fetch. Nested native Ghidra delay slots cannot
represent that state.

`C6000PipelineCompiler` builds a finite p-code control-flow graph whose state contains
the physical fetch address, pending instruction phases, pending branches, software-loop
load/fetch/drain state, multi-cycle idle count and preceding E1 register-write hazards.
It uses each instruction's existing raw p-code, preserving exact arithmetic, rounding,
predication, register aliases and status event bits. It retimes the architectural
effects instead of replacing floating-point operations with host arithmetic or opaque
helpers.

The phase contracts currently implemented are:

| Family | Operand capture | Architectural effect |
| --- | --- | --- |
| Supported scalar operations | E1 | E1 register write |
| MPY / MPYSU / MPYU / MPYUS | E1 | E2 register write |
| MPYLI | E1 | Simultaneous E4 register-pair write; .M occupancy only in E1 |
| ADDSP / SUBSP / MPYSP | E1 | E4 result and sticky event flags |
| SPDP / ABSDP / RCPDP / RSQRDP | E1 | Low word and FAUCR E1; high word E2 |
| DPSP / DPINT / DPTRUNC / INTSP / SPINT / SPTRUNC / MVD | E1 | E4 result and applicable status events |
| INTDP / INTDPU / MPYSP2DP | E1 | Low word and status E4; high word E5 |
| DP comparisons | Low words E1, upper words E2 | Result and FAUCR E2 |
| ADDDP / SUBDP | Both low words E1; both high words E2 | Low word and FADCR E6; high word E7 |
| MPYSPDP | SP source E1/E2, DP low E1/high E2 | Low word and FMCR E6; high word E7 |
| MPYDP | src1 low E1/E2, high E3/E4; src2 low E1/E3, high E2/E4 | Low word and FMCR E9; high word E10 |
| MVC ILC/RILC | E1 | Named register E1; loop-counter interface E4 |
| DINT / RINT | E1 | E1 GIE/SGIE fields, preserving unrelated CSR/TSR bits |
| Loads | E1 address and base inputs | Base update E1; memory read E3; result E5 |
| Stores | E1 address, data and base inputs | Base update E1; memory write E3 |
| B / BNOP | E1 predicate and target | Landing after five delay advances, at C+6 |
| BDEC / BPOS | E1 predicate, signed counter and target | BDEC decrement E1 iff taken; transfer after five delay advances, at C+6 |

Same-cycle loads read memory before stores commit. Long-latency results and flag events
retain their issue predicate. Flag events merge into the *current* status register at
writeback, even if software cleared the flag after issue. NOP, BNOP and ADDKPC cycle
counts, protected loads and compact fetch headers advance the same state machine. A
branch landing can interrupt a multi-cycle NOP. Up to six transfers can remain pending.
E1 X-path hazards insert a stall without advancing any pending pipeline phase (SPRUFE8B
3.5, 3.8.3–3.8.4, 3.10.2.2 and 4.2).

BDEC and BPOS use the raw instruction's actual transfer decision, including its signed
counter test, rather than treating an enabled predicate as a taken branch. Zero
satisfies both instructions' `counter >= 0` condition; BDEC's existing raw subtraction
is committed once in E1 only when the transfer is taken. Same-packet readers and
predicate/counter changes sample the pre-write values. Both instructions reject ADDKPC
companions. BDEC rejects potential simultaneous E1 counter writers unless complementary
predicates prove the writes exclusive (SPRUFE8B pp. 159-160, 170-171; section 3.7).

## DP source ports and software loops

The DP phases follow SPRUFE8B 4.2.7–4.2.16 and the individual instruction pipeline
tables. Operand words are captured independently before that cycle's writes. The
reversed .S SUBDP spelling swaps displayed operands but retains the encoded ports'
timing. An instruction predicate is captured at issue even when its register aliases a
later-read operand word. Sticky events merge at the low-result phase; the other status
lane and any intervening MVC remain visible. MVD uses E4, as specified in its pipeline
table, not the E2 timing of integer multiplies.

**Repeated DP port reads currently require stability.** MPYDP and MPYSPDP may read a
word more than once. Any possible write between its first and last read is refused. The
compiler does not replace changing repeated reads with one arbitrary sample or
approximate a partial-product datapath. This is a restricted, checked timing contract,
not support for every legal DP schedule.

Normal SPLOOP, SPLOOPD, SPLOOPW, SPMASK and SPKERNEL execute through an explicit
loop-buffer state machine (SPRUFE8B 7.4, 7.7–7.10, 7.14–7.15). The source is fetched
once; cached instructions overlap by initiation interval, masked setup remains a
once-only program operation, and drain disables cached operations in source order.
Source NOPs retain decoded cycle counts. SPLOOPD suppresses the first three body-cycle
tests and observes delayed MVC counter loads. ILC loads too close to SPLOOP and ILC
accesses inside a counted loop body are refused under 7.9.7; their
implementation-dependent or exception behavior is not guessed. SPLOOPW samples its
predicate before E1 writes and uses its value three advances later; it does not access
or modify ILC/RILC. Early while termination stops buffered repeats and lets the first
program-memory invocation complete. Zero/one counted iterations pad to the last loading
boundary. A taken branch idles the non-reloading buffer after its five delay slots;
previously issued writes still mature. TSR.SPLX tracks buffer activity independently of
fetch.

Normal post-loop execution resumes at the SPKERNEL delay, capped at the end of the
epilog (SPRUFE8B p.481, 7.9.4, 7.12). It does not add six cycles for a fresh
PG-through-DC fetch: the general pipeline diagram in 4.1.4 does not establish that a
suspended sequential stream is discarded. Abrupt SPLOOPW exits retain their separate
conservative transition contract; nested reloads are unsupported. No C674x
silicon-equivalence claim is made. A required X-path or AMR stall for a buffered
instruction is refused because 7.15.2 specifies LBX/MSX exception behavior, not an
automatic stall. Program memory instructions retain automatic stalls; unchanged
complementary sampled predicates are permitted for buffered E1 readers. The separate
`C6000LoopBuffer` helper reports abstract buffer issue cycles and exposes an external
post-body fetch window; it is not a complete frontend or instruction writeback emulator.

## Entry and exit contracts

This representation requires an explicit per-function entry review. The default-enabled
`C6000 Reviewed Pipeline Schedules` analyzer activates only recorded, unchanged contracts;
discovering a function never supplies a contract. A function boundary does not imply an
empty pipeline. Before enabling it, establish that no incoming writes
or transfers remain pending, and supply the GPRs actually written by the preceding E1
packet. The latter determine an incoming X-path stall. Record the supporting caller/tail
evidence in the program:

```java
C6000PipelineSchedules.enable(program, function,
    "Reviewed caller and return-tail evidence for this entry",
    Set.of("A4", "A6"), monitor);
```

Use an empty set only when there are no incoming E1 hazards. Conditional incoming
hazards must be resolved for the selected entry contract; they are not guessed from a
prototype. A return with pending effects is refused rather than dropping effects that
belong in the caller.

Compilation completes before the listing changes. Enabling is transactional, retains the
entry's comments, references and explicit flow overrides, expands the body to scheduled
physical code, and records the contract in program options. Repeating the same enable
operation is idempotent. Only the entry instruction's opt-in context changes; ordinary
raw instruction semantics stay available at every physical address.

### Review, record and apply

`C6000ReviewPipelineSchedules.java MANIFEST REPORT` produces a read-only plan.
Each function supplies `drained_entry_evidence`, an explicit `previous_e1_writes`
array, and SHA-256-pinned full-fetch `entry_sources` windows supporting the entry
review. These are reviewer assertions about the selected caller/entry paths, not
an automatically inferred empty pipeline. Account for earlier late writes, pending
transfers, alternate entry paths and the actual preceding E1 register writers.

The manifest uses schema 1 and the program's exact `language_id`. For example:

```json
{
  "schema": 1,
  "language_id": "C6000:LE:32:default",
  "functions": [{
    "entry": 4096,
    "drained_entry_evidence": "Describe the reviewed caller-path drainage proof here",
    "previous_e1_writes": [],
    "entry_sources": [{"start": 8192, "length": 32, "sha256": "REPLACE_WITH_SOURCE_SHA256"}]
  }]
}
```

Source windows must start and end on 32-byte fetch boundaries. The report records
supported schedules and precise refusal reasons. Successful compilation alone does
not prove entry drainage. Reviewed activation also requires complete function
ownership of the covered code; repair/review incomplete bodies separately.

After reviewing the report, pass its SHA-256 with an explicit action:

```
C6000ReviewPipelineSchedules.java MANIFEST REPORT record REVIEW_SHA256
C6000ReviewPipelineSchedules.java MANIFEST REPORT apply REVIEW_SHA256
```

`record` stores approved pending contracts without changing instruction context.
The analyzer activates them on subsequent function analysis. `apply` records and
activates the approved batch directly, transactionally, with ordinary auto-analysis
suppressed during the worker. Both preserve the reviewed report beside the output.
A changed manifest, review hash or generated plan refuses before application.

Bindings include full fetch bytes, decode context, instruction flow overrides,
function/data ownership, references into and out of the scope, entry evidence and
the generated schedule's p-code. Added interior entry points, changed caller bytes,
or a different compiled schedule invalidate the binding. Injection revalidates it
even when an analysis pass has not run. A stale schedule produces a specific error;
it never silently resumes sequential writeback. Re-review and apply a new report
after intentional changes. Repeated unchanged analysis is read-only.

The existing `C6000PipelineSchedules.enable` API still accepts an explicit drained
entry attestation and now creates the same source binding. Older enabled programs
without bindings require an explicit repeat of that API after reviewing their
entry assumptions; reopening a program does not silently adopt an old contract.
This compatibility API binds the function scope but has no pinned caller windows;
use the report workflow when the entry proof depends on caller source bytes.
No new architectural registers, destination shadows or SLEIGH context fields are
introduced. Instruction-step emulators still use raw instruction semantics.

The entry invokes a dynamic CALLOTHER fixup registered through the processor
specification's injection library. The native decompiler receives the scheduled p-code
CFG and a captured return target. Stock instruction-step emulators do not expand this
dynamic payload: execute `Result.code()` through a p-code executor for schedule
validation. `cycleStarts()` and `stallTargets()` provide nonarchitectural trace points,
which the decompiler can eliminate.

## Explicit limits

Unsupported timing contracts fail closed. These include changing repeated DP source
reads, nested/predicated loop reloads (SPKERNELR/SPMASKR), loop interrupt entry/restart
in this compiler, calls, unresolved register transfers other than a captured B3 return,
special control-register side effects, and unproved dynamic control-flow scopes. No
whole-ISA pipeline-completeness claim is made. Raw instruction decode remains available
for unsupported functions. Other function ownership and defined data are never absorbed
into a schedule. Schedules beyond 4096 states or one million p-code operations are
refused; increasing the decompiler timeout is not a workaround.

`pipeline-contracts.py` / `C6000PipelineContractTest.java` reproduce the issue #16
parallel-input, MPYSP-result and updating-load hazards in each endian mode, then
verify corrected values through reviewed analyzer activation and native
decompilation. They also check read-only reporting, review hashes, unsupported
phases, stale source/context/flow, retained annotations and idempotence.

`tests/fixtures/pipeline-schedule.py` and `C6000PipelineSemanticsTest.java` check 18
executions and five refusals: old parallel reads, E4/E5 writeback, updating-load
aliases, memory timing, six overlapping branches, captured predicates and return
targets, predicated delayed writes, sticky flags, X-path stalls including incoming
hazards, both endian modes, refusal safety, idempotent enablement and native
decompilation. The focused `pipeline-float.py` / `C6000PipelineFloatTest.java` corpus
reuses the existing independent MPYSP expectations for 120 cases per endian mode. It
clears FMCR between issue and E4, checking captured rounding and delayed event flags
with NaNs, infinities, signed zeros, overflow, underflow and source/destination aliases.

`pipeline-dp.py` / `C6000PipelineDpTest.java` exercise split DP writes, late operands,
reversed SUBDP, predicate/operand aliases, MVD, interrupt fields, resource occupancy and
refusal without context mutation. `pipeline-dp-arithmetic.py` uses the exact rational
oracle for delayed results, aliased destinations, all rounding modes and status clears
between capture and writeback. `pipeline-loop.py` checks intervals 1/2/3/6/14,
zero/one/many iterations, delayed counter setup, while sampling, buffered floating-point
memory effects, branch aborts and all eight compact NOP counts in both endian modes.
Selected DP/loop cases also pass through the native decompiler at the unchanged
30-second limit.

`pipeline-counter-branch.py IMAGE CASES.json [be]` and
`C6000PipelineCounterBranchTest.java CASES.json` check 60 cases per endian: 56
executions and four refusals. They cover negative/zero/positive counters, E1 decrement
visibility, captured and inverted predicates, safe parallel counter writes for BPOS,
backward BDEC loops, overlapping transfers and ADDKPC/conflicting-writer refusals.
Acyclic cases count raw subtractions to reject duplicated BDEC arithmetic; refusal
checks require unchanged entry bytes and disabled schedule context.

### Proved path feasibility

The straight-line prefix proof starts with unknown registers and uses Ghidra's integer
p-code arithmetic, packet input snapshots and documented write phases. Memory, floating
results, unknown predicates and collisions invalidate constants. Only an unconditional
counted loop with a proved positive loading-stage bound can lose an impossible
early-stop edge; its counter decrement and all later states remain. Unknown proofs
retain the existing resource rejection.

A separate finite zero/nonzero domain tracks the six predicate GPRs and old-value copy
aliases. Facts fork on the pre-E1 snapshot, invalidate at actual commit phases, and
widen at backward transfers and loop-time wraps. Counter branches retain their actual
raw taken condition and do not infer predicate truth from a failed sign test. This
pruning never permits a resource collision or flushes a pending effect early.

`loop-counter-proof.py` / `C6000LoopCounterProofTest.java` check known and unknown
counts, both parallel setup forms, E4 counter visibility and preserved refusals.
`pipeline-predicate-facts.py` / `C6000PredicateFactsTest.java` check old-value copies,
parallel predicate changes, delayed writes, unknown arithmetic and conservative
widening. The latter fixture uses TI's assembler (`TI_C6000_BIN` can select it). The
pending-return guard remains required: stores and other effects may genuinely cross a
function boundary, requiring a caller continuation rather than an early writeback
approximation.

## Updating loads and cross-return traces

Updating loads capture the transfer address before modifying the base. Their base and
data outputs retain distinct E1 and E5 values even when registers alias. The scheduler
observes individual raw p-code writes and commits them at their phases; it does not
duplicate the address or load arithmetic. Simultaneous overlapping memory/register
writes remain refused under SPRUFE8B 3.8.8 and 4.2.5/Table 4-10.

The separate read-only [caller-continuation trace API](caller-continuation-traces.md)
can carry captured STW E3 tails through an explicit immutable caller window. It exports
the endpoint and remaining E1 hazard set. It cannot be enabled as a callee-only
schedule; the ordinary pending-return refusal remains intact.

The [closed direct-call API](closed-call-traces.md) additionally proves one planned
call/link/return across explicit caller and callee windows. It carries the existing
pending effects through each boundary and remains read-only. Run both trace families and
the packet regressions with `python3 tools/verify.py --with-ti --jobs 2`; see
[verification](verification.md#reproducing-release-verification) for prerequisites.

For a source-bound caller-entry and callee-scope contract, see the
[strict caller/store-tail API](caller-tail-traces.md). It validates the physical caller
evidence and preserves pending effects through the declared continuation.
