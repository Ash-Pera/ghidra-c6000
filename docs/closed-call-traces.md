# Read-only closed-call traces

`C6000PipelineCompiler.compileClosedCallTrace(program, caller, plan)` compiles one
explicit proved call, its callee return, and the caller continuation into one read-only
schedule. It preserves the raw instruction p-code and existing pipeline state through
both ownership boundaries. The returned result is not a function schedule and cannot be
installed with `C6000PipelineSchedules.enable`. Ordinary compilation continues to refuse
unplanned transfers to another owner.

## Plan and scope

`compileClosedCallsTrace(program, caller, plans)` accepts one to sixteen sequential,
nonrecursive leaf calls. Each `ClosedCallPlan` declares a call site, callee window,
link writer, continuation and callee return. All plans share the same caller window,
actual trace start, drained entry/hazards and endpoint. There is no fresh entry or
pipeline restart between calls. Repeated calls can share an identical hashed callee
window. The scheduler's state includes the active call site, so a shared return PC
selects the correct invocation's continuation. Nested calls remain refused.

The single-call API delegates to the same implementation and retains its result type.
The plural result provides `contracts()`, `proofs()` and the existing boundary metadata.
Neither result is an installable multi-owner function contract.

A bounded plan supplies `stopPc` equal to the caller window's exclusive end. A complete
caller plan supplies `callerReturnPc`; its E1-captured register target determines the
exit. B3 retains its existing return interpretation. Another GPR, such as A0, must be
proved to hold the entry B3 value through exact register copies. Possible nonpreserving,
partial, colliding or late writes invalidate that provenance. Memory round trips are
not assumed to preserve it. The same provenance follows CALLP links to their matching
internal returns; unrelated register branches remain unresolved.

Each `TraceWindow.fetchBytesSha256` hashes bytes from `start & ~31` through
`(end + 31) & ~31`, exclusive. These full fetch packets include compact decoding
context. Execution permission remains restricted to the declared instruction window.
Every byte of an instruction must retain the declared function owner and lie in its
body; defined data may not overlap any instruction byte. Isolated decoder fields come
directly from the hashed physical header, including RS, DSZ, PROT, BR, SAT and compact
p-bits; stale stored context is ignored without being changed. Physical fetch-layout
alignment and instruction width must match. Explicit `UnownedSpan` entries may identify
code with no database owner; they require evidence and share the window's byte hash. A
span is refused if an owner exists. Their endpoints must be instruction boundaries;
partial instructions, owner overlap and data overlap are refused. They do not expand any
function or change an annotation.

## Call and link proof

Each call is an unconditional `B` or `CALLP`. The callee returns unconditionally
through B3, or A3 for `.S1 CALLP`. Calls may occur inside an execute packet; the start
and continuation must be packet starts. Direct and register `B` targets, including B3
and cross-path operands, are supported when raw p-code proves the packet-old target
equals the declared callee entry. The schedule captures the actual E1 target, so
same-packet and delay-slot register overwrites cannot redirect it.

The constant evaluator follows the six call/delay advances and must derive the declared
link register equal to the continuation. Exact unconditional E1 `MVK` / `MVKL`, `MVKH`
and `ADDKPC` writes are supported. The final writer must match `linkPc`; it may occur
before the final delay advance. ADDKPC's inserted NOPs count as real advances. Wrong or
missing halves, competing writers, pre-link late writes and callee link-register
clobbers still refuse. After each call, the proof invalidates all possible callee
outputs and incoming pending writes. Possible late register outputs shadow subsequent
prefix proofs conservatively, while unaffected constants can survive a call. No ABI
preservation rule or drained-return assumption supplies a missing constant.

`CALLP` writes A3/B3 in E1 and inserts five idle advances. Its link is the next physical
execute packet, including parallel peers and skipped fetch headers. The scheduler
keeps its CALLP invocation until a return register is proved to hold that call's link.
It refuses a CALLP with another branch pending, a nested invocation, software-loop
execution, a conflicting multicycle NOP generator or a simultaneous link writer.
The single-owner scheduler can execute such CALLP closures without an external call
plan; transfers to other owners still require the explicit closed-call API.

These rules follow SPRUFE8B 3.5, 3.7, 3.8.10, 4.2.6 and the CALLP (p.172),
B/MVK/MVKH/ADDKPC instruction descriptions.

Inside the callee, direct `B`, `BNOP`, `BDEC` and `BPOS` edges may be conditional,
forward or backward. Every target must be a validated execute-packet start inside the
callee's hashed ownership window. Their existing predicates, delay work and pipeline
state are retained; internal redirects do not generate call-boundary markers. Undeclared
calls, indirect callee jumps, undeclared returns, caller control edges, software loops
and IDLE remain refused. Branch-target packets crossing fetch packets are refused:
their fetch stall or compact target restriction is not approximated. Eight-instruction
packets involving a compact header are also refused (SPRUFE8B 3.10.4, 4.2.6).

## Pending effects and boundaries

The scheduler carries its existing flights, captured inputs and predicates, outputs,
memory operations, branch ages and E1 hazards across both boundaries. It does not flush
or restart the pipeline. Existing unit, port, repeated-read, write-collision and return
guards still apply. A bounded endpoint must be free of pending effects and export an
exact unconditional set of outgoing E1 hazards. A complete caller return retains the
ordinary pending-effect refusal.

`ClosedCallBoundary` records a p-code marker, edge kind, branch PC, and a live
`capturedTarget` varnode. At `CALL_ENTER` this is the proved A3/B3 link register after the link instruction; at
`CALL_RETURN` and `CALLER_RETURN` it is the actual E1-captured return target.
`expectedTarget` is the statically proved continuation for the first two edges, and null
for the caller's dynamic final return. Effects retain their original instruction bytes,
age, remaining advances and captured predicate. STW effects also expose the exact
captured address, value and inputs using the continuation trace API's `PendingStore`
record. Boundary hazards expose their actual enable varnodes; they are not replaced by
an unconditional union.

`ClosedCallTraceResult.proof()` (or each plural `proofs()` entry) supplies the call PC, source register (null for a direct
call), expected destination, continuation, ordered delay-window link-writer PCs and a
live E1-captured destination varnode. Inspect that varnode at `CALL_ENTER`. Existing
`ClosedCallBoundary.capturedTarget` semantics remain unchanged.

The focused fixture exercises split links, B5/B3/cross-path calls, target overwrites,
constant-proof refusals, conditional forward paths, an internal counter loop and a
late E4 MPYLI pair result and an E3 store across the
return, the final-delay B3 cross-path stall at callee entry, saving/restoring the
caller's entry B3, both endians, byte/hash/link/control refusals and exact unowned-span
ownership. The timing rules follow TI SPRUFE8B 3.5, 3.7, 3.10.2 and 4.2. A bounded trace
proves only its declared path; it is not evidence that the rest of a caller function or
other calls have been compiled.

## Synthetic regression

Generate with `python3 tests/fixtures/closed-call.py IMAGE CASES.json [be]`. Import at
`0x1000` with the matching default C6000 language and `-noanalysis`, then run
`C6000ClosedCallTraceTest.java CASES.json RESULTS.json`. Require
`CLOSED_CALL_TRACE_TEST_OK`; no external assembler or firmware is needed. The release
runner includes both endian variants; use
`python3 tools/verify.py --only closed-call --jobs 2` for a focused rerun.

`pipeline-calls.py` / `C6000PipelineCallsTest.java` additionally execute CALLP on both S
units, compact forms and both RS settings, packet peers and header seams, repeated and
distinct callees, pending return stores and saved-link returns. Refusal cases cover
unknown or clobbered saved links, nonlocal returns, late CALLP-link corruption, pending
branches, link collisions and conflicting NOP generators. Use
`python3 tools/verify.py --only pipeline-calls --only closed-call --jobs 2`.
