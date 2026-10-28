# C674x software-loop conformance

`C6000LoopBuffer` schedules loop-buffer issue cycles over decoded Ghidra instructions.
It does not execute their p-code. Its contract follows
[TI SPRUFE8B, chapter 7](https://www.ti.com/lit/ug/sprufe8b/sprufe8b.pdf), particularly
sections 7.7–7.13.

The [exact packet compiler](pipeline-schedules.md) separately executes supported normal
loops with instruction writeback phases. Its
[post-loop dispatch contract](post-loop-dispatch.md) is distinct from the helper's
abstract fetch window.

## Loop-buffer contract

| Behavior | API or rule |
|---|---|
| Source packets and idle cycles | `fromProgram` extracts execute packets, compact parallel bits and decoded NOP durations. |
| Initiation-interval overlap | `operationsAt` distinguishes source and buffered operations; SPMASK suppresses the selected units. |
| Counted termination | `replayCountedDetailed` models the initial SPLOOP ILC test/decrement and the SPLOOPD first-three-cycle grace period. |
| Short final loading stage | Zero/one-count loops retain idle cycles through the last loading-stage boundary. |
| While termination | `replayWhileDetailed` samples its predicate with a three-cycle delay and leaves ILC/RILC unchanged. |
| Post-body fetch | `ReplayResult.firstPostBodyCycle` and `Cycle.postBodyFetchEnabled` expose the fetch window and epilog overlap. |
| Post-body masking | `Cycle.overlayPostBody(packet)` filters buffered operations using the caller-selected program packet. |
| Counted interrupt drain | An eligible pending, unblocked interrupt preserves ILC, disables post-body fetch and yields `INTERRUPT_DRAINED`. |
| While interrupt drain | Delayed predicate tests continue during drain; termination can yield `INTERRUPT_AT_POST_BODY`. |
| Interrupt restart | `InterruptHandoff` records the SPLOOP packet, ILC and SPLX; restart reverses source/buffer masking and uses the SPLOOP initial control for SPLOOPD. |
| Suppressed restart operations | Masked BNOP/ADDKPC and protected loads retain idle duration without issuing suppressed effects. |
| Immediate reload | `replayImmediateReload` samples the outer predicate and visible RILC for the supported SPKERNELR case. |

Cycle zero is the cycle **after** the SPLOOP execute packet.
`firstPostBodyCycle == cycles` means fetching resumes on the next cycle after the
reported trace. Operations listed in one cycle are simultaneous. An executor must
advance through an `idleOnly` operation's cycles without executing that instruction's
p-code.

## Using the replay script

In Script Manager, select a decoded SPLOOP instruction and run `C6000LoopReplay.java`.
For a headless run, supply that instruction's address as the first argument:

```text
C6000LoopReplay.java LOOP_ADDRESS COUNT CYCLE_LIMIT
```

For counted loops, COUNT is initial ILC. For SPLOOPW, it is the number of predicate
samples that remain true. COUNT defaults to 2 and CYCLE_LIMIT to 512.

| Optional argument | Counted loops | SPLOOPW |
|---|---|---|
| Fourth | First pending, unblocked interrupt cycle. | Initial ILC, traced without controlling termination. |
| Fifth | `restart`, after the interrupt argument. | First pending, unblocked interrupt cycle. |
| Sixth | — | `restart`, after the interrupt argument. |

Restart traces model return with saved SPLX=1. `C6000LoopModelTest.java` can check all
decoded loop bodies in an imported program. These helpers report issue order and
loop-control state; instruction writeback and handler entry remain the executor's
responsibility.

## Remaining emulator state

1. **Program counter and execute packets.** The caller must choose the
   post-body packet, including branch delay slots and taken targets, then pass
   that packet to `overlayPostBody`. The scheduler reports fetch enable timing
   but does not guess the PC. Decode packet headers before constructing an
   execute packet.
2. **Instruction execution and pipeline.** Apply packet operands with
   simultaneous-read semantics and the instruction-specific write latencies
   from SPRUFE8B chapter 4. Loads, stores, branches, floating-point results,
   and control-register writes mature at different phases. The loop scheduler
   reports when an operation is issued, not when its result becomes
   visible.
3. **Interrupt completion and architectural return.** Counted-loop buffer draining
   ends with preserved `ILC` and disabled program-memory fetch; `SPLOOPW`
   draining can instead hand the interrupt to the first post-body instruction.
   The emulator must finish pending register writes, write the saved packet
   address to `IRP` or `NRP`, preserve `SPLX` in `ITSR` or `NTSR`, and restore
   those registers on return. Restart replay handles source/buffer mask
   reversal and `SPLOOPD` initial control; the caller must suppress
   instructions parallel with the restarted `SPLOOP` packet. The scheduler
   handles `BNOP`, masked `ADDKPC`, and protected-load idle cycles.
   Architectural blocking and pending interrupt state are supplied by the
   caller for either loop kind. The model does not determine handler-entry
   timing or write the CPU control registers itself.
4. **Remaining nested reload cases.** The dedicated immediate reload entry
   point covers predicated `SPLOOP` with `SPKERNELR` when both the first and
   subsequent invocation counts finish the loading stage. It samples the
   caller's outer predicate four cycles before the last kernel boundary and
   reads the caller's visible `RILC` at the boundary. `SPLOOPD`, zero or short
   reload counts, delayed `SPMASKR` reload, and branch-based program-fetch
   disabling still need models. A delayed reload also needs a second LBC
   because the old drain and new prolog can have different offsets.
   `replayCountedDetailed` continues to reject reloadable loops.
5. **Exceptions and architectural validation.** Exceptions abort the buffer
   without a normal epilog. The emulator must also enforce the documented
   resource, register-access, `SPMASKR`/`SPKERNELR`, and reload-overlap
   restrictions. Ghidra's static decoder does not enforce all of them.

## Reproducible fixtures

`tests/fixtures/loop-delay.s` covers restart idle cycles for displacement BNOP, masked
register BNOP, masked ADDKPC and a protected LDW. It also includes TI Example 7-15's
immediate reload sequence. Assemble the `.text` section with GNU
`tic6x-unknown-elf-as -march=c674x` and extract it using
`tic6x-unknown-elf-objcopy -O binary -j .text`. Import the result at `0x1000` with
`C6000:LE:32:default`, then run `C6000LoopDelayTest.java` and
`C6000ImmediateReloadTest.java`.

The scripts check issue effects and idle-cycle positions. The protected-load case uses a
full32 LDW in a compact packet with PROT=1; the header rule also applies to compact
loads. The immediate-reload fixture includes NOP 4 and checks two or three invocations
in 20 or 27 cycles, including simultaneous old STW and new MV issue.

For the exact compiler, `pipeline-loop.py` and `pipeline-postloop.py` exercise
normal-loop loading, drain, dispatch and supported writeback phases. See
[verification](verification.md) for the release runner and TI-tool requirements.

Full emulator qualification also needs independent hardware or reference traces for
zero/one iterations, legal initiation intervals and SPKERNEL delays, masks, early while
exits, interrupt restart and both reload forms. Compare issue and writeback cycles,
ILC/RILC/LBC/SPLX, PC and memory effects. Passing the supplied synthetic fixtures does
not establish these unmodeled behaviors.
