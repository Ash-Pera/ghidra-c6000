# Read-only closed direct-call traces

`C6000PipelineCompiler.compileClosedCallTrace(program, caller, plan)` compiles one
explicit direct call, its callee return, and the caller continuation into one
read-only schedule. It preserves the raw instruction p-code and existing
pipeline state through both ownership boundaries. The returned result is not a
function schedule and cannot be installed with `C6000PipelineSchedules.enable`.
Ordinary compilation continues to refuse unplanned transfers to another owner.

The immutable `ClosedCallPlan` specifies the language, caller and callee code
windows and owner entry points, trace start, direct call, link instruction,
continuation, callee return, drained entry and preceding E1 hazards, and evidence.
A bounded plan supplies `stopPc` equal to the caller window's exclusive end. A
complete caller plan instead supplies `callerReturnPc`; the actual captured B3
value at that final return determines its exit. The caller can save and restore
its original B3 using its normal instructions.

Each `TraceWindow.fetchBytesSha256` hashes bytes from `start & ~31` through
`(end + 31) & ~31`, exclusive. These full fetch packets include compact decoding
context. Execution permission remains restricted to the declared instruction
window. Every byte of an instruction must retain the declared function owner
and lie in its body; defined data may not overlap any instruction byte.
Isolated decoder fields come directly from the hashed physical header, including
RS, DSZ, PROT, BR, SAT and compact p-bits; stale stored context is ignored without
being changed. Physical fetch-layout alignment and instruction width must match.
Explicit `UnownedSpan` entries may identify code with no database owner; they
require evidence and share the window's byte hash. A span is refused if an owner
exists. Their endpoints must be instruction boundaries; partial instructions, owner
overlap and data overlap are refused. They do not expand any function or change
an annotation.

The initial contract supports straight-line windows with one unconditional
direct `B` call, an unconditional `B`/`BNOP B3` callee return and an optional final
caller B3 return. Branch-target execute packets crossing fetch packets are refused: their fetch
stall or compact target restriction is not approximated. Eight-instruction
packets involving a compact header are also refused (SPRUFE8B 3.10.4, 4.2.6).
Other control edges, software loops, missing ownership,
conflicting defined data and incomplete endpoints are refused. The final delay
cycle must contain an unconditional E1 `ADDKPC` writing B3. The existing constant
proof evaluator must derive exactly the continuation from that instruction's
raw p-code with all architectural inputs unknown. Competing link writers, any
callee B3 writer and pre-link late B3 writers are refused. This is a proof of the
actual return target, independent of an ABI guess or a caller-supplied B3 value.

The scheduler carries its existing flights, captured inputs and predicates,
outputs, memory operations, branch ages and E1 hazards across both boundaries.
It does not flush or restart the pipeline. Existing unit, port, repeated-read,
write-collision and return guards still apply. A bounded endpoint must be free
of pending effects and export an exact unconditional set of outgoing E1 hazards.
A complete caller return retains the ordinary pending-effect refusal.

`ClosedCallBoundary` records a p-code marker, edge kind, branch PC, and a live
`capturedTarget` varnode. At `CALL_ENTER` this is B3 after the link instruction;
at `CALL_RETURN` and `CALLER_RETURN` it is the actual E1-captured return target.
`expectedTarget` is the statically proved continuation for the first two edges,
and null for the caller's dynamic final return. Effects retain their original
instruction bytes, age, remaining advances and captured predicate. STW effects
also expose the exact captured address, value and inputs using the continuation
trace API's `PendingStore` record. Boundary hazards expose their actual enable
varnodes; they are not replaced by an unconditional union.

The focused fixture exercises a late E4 MPYLI pair result and an E3 store across
the return, the final-delay B3 cross-path stall at callee entry, saving/restoring
the caller's entry B3, both endians, byte/hash/link/control refusals and exact
unowned-span ownership. The timing rules follow TI SPRUFE8B 3.5, 3.7, 3.10.2 and
4.2. A bounded trace proves only its declared path; it is not evidence that the
rest of a caller function or other calls have been compiled.
