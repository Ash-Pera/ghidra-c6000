# Read-only closed-call traces

`C6000PipelineCompiler.compileClosedCallTrace(program, caller, plan)` compiles one
explicit proved call, its callee return, and the caller continuation into one read-only
schedule. It preserves the raw instruction p-code and existing pipeline state through
both ownership boundaries. The returned result is not a function schedule and cannot be
installed with `C6000PipelineSchedules.enable`. Ordinary compilation continues to refuse
unplanned transfers to another owner.

## Plan and scope

The immutable `ClosedCallPlan` specifies the language, caller and callee code windows
and owner entry points, trace start, call instruction, final link instruction, continuation, callee
return, drained entry and preceding E1 hazards, and evidence. A bounded plan supplies
`stopPc` equal to the caller window's exclusive end. A complete caller plan instead
supplies `callerReturnPc`; the actual captured B3 value at that final return determines
its exit. The caller can save and restore its original B3 using its normal instructions.

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

The contract includes one unconditional `B` call, an unconditional `B` / `BNOP B3`
callee return and an optional final caller B3 return. The call and continuation must be execute-packet starts. The call can use a direct address
or a register, including B3 and cross-path operands. A conservative constant evaluator
executes the straight-line caller prefix's raw p-code with all architectural inputs
unknown. It must prove the destination equals the declared callee entry **before** the
call packet's E1 writes. Memory-derived, unknown, conflicting or incorrectly assembled
targets cannot establish that proof. The schedule captures the actual E1 destination;
a same-packet or delay-slot overwrite cannot redirect the call.

The same evaluator follows the six call/delay advances and must derive B3 equal to the
continuation. Unconditional exact E1 `MVK` / `MVKL`, `MVKH` and `ADDKPC` link writes are
supported. The last link writer must be the declared `linkPc` in the final delay cycle.
MVK sign extension, MVKH preservation of the low half, old packet reads, collisions
and late effects use the existing raw-p-code/phase model. Missing or wrong halves,
conditional link writers, pre-link late B3 writers and any callee B3 writer are refused.
No caller-supplied register value or ABI convention substitutes for these proofs
(SPRUFE8B 3.5, 3.7, 3.12, 4.2.6 and the B/MVK/MVKH/ADDKPC instruction descriptions).

Inside the callee, direct `B`, `BNOP`, `BDEC` and `BPOS` edges may be conditional,
forward or backward. Every target must be a validated execute-packet start inside the
callee's hashed ownership window. Their existing predicates, delay work and pipeline
state are retained; internal redirects do not generate call-boundary markers. Additional
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
`capturedTarget` varnode. At `CALL_ENTER` this is B3 after the link instruction; at
`CALL_RETURN` and `CALLER_RETURN` it is the actual E1-captured return target.
`expectedTarget` is the statically proved continuation for the first two edges, and null
for the caller's dynamic final return. Effects retain their original instruction bytes,
age, remaining advances and captured predicate. STW effects also expose the exact
captured address, value and inputs using the continuation trace API's `PendingStore`
record. Boundary hazards expose their actual enable varnodes; they are not replaced by
an unconditional union.

`ClosedCallTraceResult.proof()` supplies the call PC, source register (null for a direct
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
