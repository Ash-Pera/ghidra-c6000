# Exact packet schedules (explicit opt-in)

C6000 execute packets read their inputs before parallel writes become visible.
A branch can issue before an earlier branch lands. The second branch remains
pending when the first transfer redirects instruction fetch. Nested native
Ghidra delay slots cannot represent that state.

`C6000PipelineCompiler` builds a finite p-code control-flow graph whose state
contains the physical fetch address, pending instruction phases, pending
branches, multi-cycle idle count and preceding E1 register-write hazards. It
uses each instruction's existing raw p-code, preserving exact arithmetic,
rounding, predication, register aliases and status event bits. It retimes the
architectural effects instead of replacing floating-point operations with
host arithmetic or opaque helpers.

The phase contracts currently implemented are:

| Family | Operand capture | Architectural effect |
| --- | --- | --- |
| Supported scalar operations | E1 | E1 register write |
| MPY / MPYSU / MPYU / MPYUS | E1 | E2 register write |
| ADDSP / SUBSP / MPYSP | E1 | E4 result and sticky event flags |
| Loads | E1 address and base inputs | Base update E1; memory read E3; result E5 |
| Stores | E1 address, data and base inputs | Base update E1; memory write E3 |
| B / BNOP | E1 predicate and target | Landing after five delay advances, at C+6 |

Same-cycle loads read memory before stores commit. Long-latency results and
flag events retain their issue predicate. Flag events merge into the *current*
status register at writeback, even if software cleared the flag after issue.
NOP, BNOP and ADDKPC cycle counts, protected loads and compact fetch headers
advance the same state machine. A branch landing can interrupt a multi-cycle
NOP. Up to six transfers can remain pending. E1 X-path hazards insert a stall
without advancing any pending pipeline phase (SPRUFE8B 3.5, 3.8.3–3.8.4,
3.10.2.2 and 4.2).

## Entry and exit contracts

This representation is enabled per function, never automatically. A function
boundary does not imply an empty pipeline. Before enabling it, establish that
no incoming writes or transfers remain pending, and supply the GPRs actually
written by the preceding E1 packet. The latter determine an incoming X-path
stall. Record the supporting caller/tail evidence in the program:

```java
C6000PipelineSchedules.enable(program, function,
    "Reviewed caller and return-tail evidence for this entry",
    Set.of("A4", "A6"), monitor);
```

Use an empty set only when there are no incoming E1 hazards. Conditional
incoming hazards must be resolved for the selected entry contract; they are
not guessed from a prototype. A return with pending effects is refused rather
than dropping effects that belong in the caller.

Compilation completes before the listing changes. Enabling is transactional,
retains the entry's comments, references and explicit flow overrides, expands
the body to scheduled physical code, and records the contract in program
options. Repeating the same enable operation is idempotent. Only the entry
instruction's opt-in context changes; ordinary raw instruction semantics stay
available at every physical address.

The entry invokes a dynamic CALLOTHER fixup registered through the processor
specification's injection library. The native decompiler receives the scheduled
p-code CFG and a captured return target. Stock instruction-step emulators do
not expand this dynamic payload: execute `Result.code()` through a p-code
executor for schedule validation. `cycleStarts()` and `stallTargets()` provide
nonarchitectural trace points, which the decompiler can eliminate.

## Explicit limits

Unsupported timing contracts fail closed. These include multi-phase DP operand
reads and split writes, software-pipelined loop controls, calls, unresolved
register transfers other than a captured B3 return, special control-register
side effects, and updating loads that alias their own destination. No whole-ISA
pipeline-completeness claim is made. Raw instruction decode remains available
for unsupported functions. Other function ownership and defined data are never
absorbed into a schedule. Schedules beyond 4096 states or one million p-code
operations are refused; increasing the decompiler timeout is not a workaround.

`tests/fixtures/pipeline-schedule.py` and `C6000PipelineSemanticsTest.java`
check old parallel reads, E4/E5 writeback, memory timing, six overlapping
branches, captured predicates and return targets, predicated delayed writes,
sticky flags, X-path stalls including incoming hazards, both endian modes,
refusal safety, idempotent enablement and native decompilation. The focused
`pipeline-float.py` / `C6000PipelineFloatTest.java` corpus reuses the existing
independent MPYSP expectations for 120 cases per endian mode. It clears FMCR
between issue and E4, checking captured rounding and delayed event flags with
NaNs, infinities, signed zeros, overflow, underflow and source/destination aliases.
