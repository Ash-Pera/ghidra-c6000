# Closed caller-continuation traces

`C6000PipelineCompiler.compileTrace(ReturnContinuation)` is an opt-in read-only
native-pcode trace API. It can retain captured STW E3 tails at a B3 return, execute an
explicitly bounded caller window, and finish with no outstanding
flights/branches/loop/idle state. It returns an explicit exit PC and the outgoing
previous-E1-write hazard set. Ordinary `compile()` and `C6000PipelineSchedules.enable()`
keep their pending-return refusal.

The API does not turn a callee into a drained function or install multi-owner p-code. No
STORE executes early. The original Flight/predicate/input slots advance through the
caller; memory still commits at its documented E3 phase. Captured address/value metadata
observes native E1 STORE operands via unique-space copies, with no replacement
arithmetic or userops.

For a stricter source-bound callee and caller-entry contract, see
[caller/store-tail traces](caller-tail-traces.md).

## Contract

Construct a fresh compiler with the exact incoming previous-E1-write set. `TraceEntry`
declares the empty incoming flight/branch pipeline and that same hazard set.
`ReturnContinuation` supplies expected initial B3, caller-function identity, ascending
contiguous execute-packet starts, stop PC, SHA256, explicit ownership policy and
evidence. SHA256 covers every enclosing 32-byte fetch packet from
`expectedEntryB3 & ~31L` through `(stopPc + 31) & ~31L`, including header words.

This version permits only headerless full32 unconditional straight-line caller
instructions; caller branches, calls, loop controls and predicates refuse. Conflicting
ownership always refuses. The unowned-window option requires separate
caller/control-flow evidence and an immutable declared window; it does not edit or infer
function ownership. Every decoded architectural B3 writer, including partial/conditional
writes, refuses. Other pending operations or unresolved control at the return also
refuse.

Before starting execution, call `TraceResult.validateEntryB3(actualInitialB3)` on the
actual executor state. Invalid entry state is a refusal before any p-code executes. The
result is valid only under the explicit drained-entry and B3 preconditions.

`TraceBoundary.pcodeIndex` is a zero-time inspection marker after the final return-delay
cycle. Each `PendingStore` records PC, age, remaining advances, captured
enabled/address/value Varnodes, original input Varnodes and instruction hex. These
locations belong to the returned trace's unique-space execution state. Disabled effects
expose enabled=0 and initialized zero address/value fields. This is not an
open-continuation serializer or a separate-frame replay API.

The endpoint must drain all memory/register/flag flights and control effects. Remaining
E1 hazards are exported, never discarded; the next scheduler must receive them. This
version requires unconditional GPR exit hazards consistent across paths, and refuses
conditional caller exit hazards.

## C representation

The trace includes caller instructions and an explicit endpoint. It is not a callee-only
C model and must never be passed to ordinary schedule enable or installed under the
original callee. A conventional sequential callee cannot express a post-return E3 store
with the same caller-visible ordering. The strict ordinary refusal remains necessary.

## Synthetic regression

Generate with
`python3 tests/fixtures/pipeline-caller-continuation.py IMAGE CASES.json [be]`.
`TI_C6000_BIN` can name the TI C6000 bin directory or cl6x executable; omission uses
`/Applications/ti/ti-cgt-c6000_8.3.15/bin`. The generator is self-contained, retains
assembly/object/compiler log beside IMAGE, and requires no external image. All
instructions use `.nocmp`; BE swaps each fullword.

Load IMAGE at `0x1000` with the corresponding C6000 endian language. Run
`C6000CallerContinuationTest.java CASES.json RESULTS.json`. Expected marker:
`CONTINUATION_CONTRACT_TEST_OK accepted=6 refused=15 executed=6 entryRefused=6`. The 21
cases cover exact E3 advances 1/2, captured data/base/predicate, E1 base updates, caller
load/store ordering, default compile/enable refusal, and invalid
target/hash/ownership/scope/drain/hazard contracts.

TI reference: [SPRUFE8B](https://www.ti.com/lit/ug/sprufe8b/sprufe8b.pdf) sections 3.5,
4.2.3/Table 4-8, 4.2.5 and 4.2.6. This qualification does not claim a silicon trace or
complete interprocedural/ISA coverage.
