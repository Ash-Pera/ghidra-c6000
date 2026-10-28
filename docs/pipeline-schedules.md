# Exact packet schedules (explicit opt-in)

C6000 execute packets read their inputs before parallel writes become visible.
A branch can issue before an earlier branch lands. The second branch remains
pending when the first transfer redirects instruction fetch. Nested native
Ghidra delay slots cannot represent that state.

`C6000PipelineCompiler` builds a finite p-code control-flow graph whose state
contains the physical fetch address, pending instruction phases, pending
branches, software-loop load/fetch/drain state, multi-cycle idle count and
preceding E1 register-write hazards. It
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
| SPDP / ABSDP / RCPDP / RSQRDP | E1 | Low word and FAUCR E1; high word E2 |
| DPSP / DPINT / DPTRUNC / INTSP / SPINT / SPTRUNC / MVD | E1 | E4 result and applicable status events |
| INTDP / INTDPU / MPYSP2DP | E1 | Low word and status E4; high word E5 |
| DP comparisons | Low words E1, upper words E2 | Result and FAUCR E2 |
| ADDDP / SUBDP | src1 and src2 low E1; src2 high E2 | Low word and FADCR E6; high word E7 |
| MPYSPDP | SP source E1/E2, DP low E1/high E2 | Low word and FMCR E6; high word E7 |
| MPYDP | src1 low E1/E2, high E3/E4; src2 low E1/E3, high E2/E4 | Low word and FMCR E9; high word E10 |
| MVC ILC/RILC | E1 | Named register E1; loop-counter interface E4 |
| DINT / RINT | E1 | E1 GIE/SGIE fields, preserving unrelated CSR/TSR bits |
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

## DP source ports and software loops

The DP phases follow SPRUFE8B 4.2.7–4.2.16 and the individual instruction
pipeline tables. Operand words are captured independently before that cycle's
writes. The reversed .S SUBDP spelling swaps displayed operands but retains
the encoded ports' timing. An instruction predicate is captured at issue even
when its register aliases a later-read operand word. Sticky events merge at
the low-result phase; the other status lane and any intervening MVC remain
visible. MVD uses E4, as specified in its pipeline table, not the E2 timing of
integer multiplies.

**Repeated DP port reads currently require stability.** MPYDP and MPYSPDP
may read a word more than once. Any possible write between its first and last
read is refused. The compiler does not replace changing repeated reads with
one arbitrary sample or approximate a partial-product datapath. This is a
restricted, checked timing contract, not support for every legal DP schedule.

Normal SPLOOP, SPLOOPD, SPLOOPW, SPMASK and SPKERNEL execute through
an explicit loop-buffer state machine (SPRUFE8B 7.4, 7.7–7.10, 7.14–7.15).
The source is fetched once; cached instructions overlap by initiation interval,
masked setup remains a once-only program operation, and drain disables cached
operations in source order. Source NOPs retain decoded cycle counts. SPLOOPD
suppresses the first three body-cycle tests and observes delayed MVC counter
loads. ILC loads too close to SPLOOP and ILC accesses inside a counted
loop body are refused under 7.9.7; their implementation-dependent or exception
behavior is not guessed. SPLOOPW samples its predicate before E1 writes and uses its value three
advances later; it does not access or modify ILC/RILC. Early while termination
stops buffered repeats and lets the first program-memory invocation complete.
Zero/one counted iterations pad to the last loading boundary. A taken branch
idles the non-reloading buffer after its five delay slots; previously issued
writes still mature. TSR.SPLX tracks buffer activity independently of fetch.

The fetch schedule includes six PG-through-DC advances when a stopped program
frontend must refill (4.1.4). This agrees with the independent emulator on
ordinary tested paths; its exact interaction with nested reloads still needs
qualification. No C674x silicon-equivalence claim is made. The separate
`C6000LoopBuffer` helper reports abstract buffer issue cycles and exposes an
external post-body fetch window; it is not a complete frontend or instruction
writeback emulator.

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

Unsupported timing contracts fail closed. These include changing repeated DP
source reads, nested/predicated loop reloads (SPKERNELR/SPMASKR), loop interrupt
entry/restart in this compiler, calls, unresolved
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


`pipeline-dp.py` / `C6000PipelineDpTest.java` exercise split DP writes,
late operands, reversed SUBDP, predicate/operand aliases, MVD, interrupt fields,
resource occupancy and refusal without context mutation. `pipeline-dp-arithmetic.py`
uses the exact rational oracle for delayed results, aliased destinations, all
rounding modes and status clears between capture and writeback. `pipeline-loop.py`
checks intervals 1/2/3/6/14, zero/one/many iterations, delayed counter setup,
while sampling, buffered floating-point memory effects, branch aborts and all
eight compact NOP counts in both endian modes. Selected DP/loop cases also
pass through the native decompiler at the unchanged 30-second limit.
