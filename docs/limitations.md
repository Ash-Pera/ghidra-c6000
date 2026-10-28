# Status and known limitations

The extension provides instruction decode, p-code and C6000-specific analysis. Its
models have different timing and execution guarantees. Use the
[verification guide](verification.md) to check the behaviors you depend on.

## Decode and analysis

**Coverage is not exhaustive.** Decode covers the documented full32 opcode maps and
supported compact formats, including legacy MVC and C64x+ LL/SL/CMTL. Unknown encodings
remain undefined. A successful sample or corpus run does not establish coverage of every
architectural encoding.

**Compact decode needs packet context.** The packet analyzer normally primes it before
disassembly. Tools that bypass auto-analysis must call `C6000PacketContext.prime` before
decoding compact slots. The `noflow` context fields prevent one instruction's header
parameters from leaking into another; see
[compact packet internals](internals.md#compact-16-bit-fetch-packets).

**Constant propagation is bounded.** Each walk is limited to 512 bytes to bound memory
use. A register-built target carried across a longer span, loaded from memory or
supplied by another routine may remain unresolved. Raw imports also need an explicit
entry before code discovery can begin.

## Packet timing and control flow

| Model | Supported behavior | Boundary |
|---|---|---|
| Default instruction p-code | Instruction effects and proved native B/BNOP/CALLP delay windows. | Parallel instructions are lifted individually; ordinary writeback latency is not scheduled. |
| [Exact packet schedules](pipeline-schedules.md) | Supported parallel reads, pending branches and register/memory/status phases through E10; normal software loops. | Reviewed drained entry and incoming E1 hazards; only unchanged recorded contracts activate automatically. Unsupported or stale contracts are refused. |
| [Loop replay](software-loop-conformance.md) | Buffer issue order, masks, loop counters and supported drain/restart behavior. | Does not execute instruction p-code, retire writes or enter interrupt handlers. |
| Read-only caller traces | Pending effects carried through explicit immutable caller/callee windows. | Bounded plans and entry proofs; not automatically installed as ordinary function schedules. |

Native delay recovery remains conservative for nested transfers, predicated full
windows, BDEC/BPOS and existing delayed-call overrides. Ghidra's stock instruction-step
emulator can fail on mixed-width delay windows; direct listing p-code execution and
native decompilation have separate checks.

Read-only trace contracts are documented for
[closed direct calls](closed-call-traces.md),
[caller continuations](caller-continuation-traces.md) and
[strict caller/store tails](caller-tail-traces.md). A function boundary or ABI prototype
does not establish an empty incoming pipeline.

## Memory and addressing

**Aligned LDW requires a word-aligned address.** Its p-code clears the low two address
bits so a propagated misaligned value cannot form an invalid four-byte RAM range in the
decompiler. Actual hardware behavior outside the documented alignment requirement is not
established by this model.

**AMR effects are modeled at instruction level.** Eligible A4–A7/B4–B7 bases wrap
through BK0/BK1, including bytewise wrapping of nonaligned transfers. Stores capture
their source before a base update. Packet timing involving AMR writes is not generally
modeled. The exact compiler refuses unsupported control-register effects and buffered
missed-stall conditions.

**Linked-word operations require an external memory monitor.** LL and SL expose the
CPU-visible transfer and named link events. CMTL receives success from a userop; the
stock instruction emulator cannot infer another core's link state.

## Floating point and arithmetic

Selected instructions model rounding modes, special values and status events, but
status-register coverage is not complete across the ISA. ADDSP/SUBSP and ADDDP/SUBDP use
FADCR; MPYSP, MPYSPDP and MPYDP use FMCR. Supported DP arithmetic uses a quad-precision
intermediate to retain DP rounding. See the
[fixture catalog](regressions.md#integer-and-floating-point-execution) for
instruction-specific execution checks.

Reciprocal estimates implement documented special cases and FAUCR flags with an
eight-bit-accurate seed. TI does not publish the seed lookup table, so ordinary results
are not proven bit-exact against hardware.

The `analysis` language variants simplify single-precision arithmetic and use an opaque
status userop. They are reading aids; use the default languages for emulation and exact
rounding/status checks.

The published RPACK2 execution rule and compiler guide specify a saturating left shift.
For the manual's `0xFEDCBA98` example this yields upper halfword `0xFDB9`, while the
worked example prints `0xFDBA`. The implementation follows the stated operation.

## Loops, interrupts and exceptions

Software-loop instructions lift to named userops and receive analyzer bookmarks. The
loop replay helper models buffer control separately from instruction execution. The
exact compiler supports normal counted/while loops, but nested reload and loop
interrupt/restart remain unsupported there. Detailed callback, reload and handoff
contracts are in the [loop-conformance guide](software-loop-conformance.md).

DINT/RINT update modeled TSR/CSR interrupt-enable fields. B IRP restores GIE and B NRP
sets NMIE; the remaining ITSR/NTSR-to-TSR restore is not modeled. IDLE emits a scheduler
event; the stock emulator does not suspend until an interrupt on its own.

SWE/SWENR transitions are instruction-level models. `NRP = inst_next` is exact when SWE
ends its execute packet. Parallel companions and simultaneous exception priority require
a packet-aware executor.

## Function ID

Only the [database generator](internals.md#function-id) is shipped. A database derived
from TI's run-time library is not distributed because its licensing must be assessed
separately.
