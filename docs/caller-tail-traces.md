# Strict caller/store-tail traces

`C6000PipelineCompiler.compileCallerTail(CallerTailPlan)` is a read-only model
of a bounded callee execution followed by its real caller continuation. It
returns `CallerTailResult.trace()` (the existing `TraceResult`) and the immutable
scope contract. It does not install a representation under the callee or relax
ordinary pending-return refusals.

A plan pins the language and full fetch-packet byte hashes for three windows:
the callee, the caller continuation, and caller-entry source evidence. Each
`TraceWindow` identifies its existing function owner and may explicitly list
exact unowned spans. Every reachable instruction byte must remain in that body
or one complete declared unowned span. Defined data may not overlap an executed
instruction; unreachable inline data is not parsed as code. The callee is free
to use the scheduler's existing internal branches and loops. Direct branches
outside its window and unresolved register branches refuse.

Instruction width, compact expansion fields and parallel bits come from the
hashed physical fetch layout, not potentially stale stored context. Instruction
and execute-packet starts, span boundaries, branch targets and compact packet
restrictions retain the strict closed-call checks. Branch-target execute packets
crossing fetch packets refuse because their fetch timing is not modeled here.
The caller continuation remains unconditional, full32, headerless and straight
line. Every architectural B3 writer in either executed scope refuses.

`CallerEntryEvidence(setup, finalIssuedPacketPc, trailingIdleAdvances, evidence)`
is mandatory. Its source window must end at the continuation. The validator
independently decodes its final issued physical execute packet and checks its
whole byte/owner/data scope. Recognized NOP, BNOP, ADDKPC, protected-load or CALLP
spans determine the trailing idle count. Without trailing idle, the final
unconditional E1 GPR writer inventory must exactly match
`TraceEntry.previousE1Writes`. With validated trailing idle, that final hazard
set must be empty. Unsupported or conditional E1 inventories refuse rather than
inventing a register-write phase. A CALLP packet and its peers execute once;
its five implicit idle advances remove their previous-E1 hazards (TI SPRUFE8B,
CALLP, page 172).

Entry drainage remains an explicit precondition supported by a separate
physical caller-path proof. The API does not infer an empty pipeline from a
function boundary, a CALLP spelling, or an ABI. Such a proof must account for
all earlier late effects, branch-delay state, the selected path and exceptional
redirects. The evidence string should identify its source and assumptions.
Before executing returned p-code, the executor must call
`trace.validateEntryB3(actualB3)` and honor the declared drained-entry contract.
The exact B3 value and data inputs may be established by caller source evidence;
they are not conventional C prototypes inferred by this API.

The existing Flight, predicate, input, address and value snapshots carry through
the B3 return. STW still commits at E3, including old values when the caller
writes the same source register. The endpoint must drain all late effects and
exports its exact outgoing previous-E1 hazards. A conventional sequential
callee cannot express these post-return stores with the same visible ordering;
the result therefore remains a bounded multi-owner trace.

The legacy `compileTrace(ReturnContinuation)` API remains compatible. It has a
weaker scope contract and is not a substitute for this strict, source-bound API.
The synthetic `caller-tail.py` fixture exercises an internal loop, store ages
1/2 across return, caller B4 replacement, exact unowned tails, unreachable inline
data, stale stored context, and scope/hash/data/header/inventory refusals.
Existing legacy continuation and closed-call fixtures remain applicable.

TI reference: [SPRUFE8B](https://www.ti.com/lit/ug/sprufe8b/sprufe8b.pdf),
sections 3.5, 3.7, 3.10, 4.2.3, 4.2.5 and 4.2.6.
