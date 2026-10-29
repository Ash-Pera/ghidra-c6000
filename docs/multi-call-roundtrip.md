# Multiple-call integer round-trip experiment

The production `compileClosedCallsTrace` API now runs `bitstream_flush` and its two
integer leaf helpers on unchanged firmware bytes with separate owners. Fresh
trace-derived C, compiled with TI, matches the original trace and an independent oracle
in all 1,056 cases. No alternate scheduler classes or scratch compiler extension are
loaded. The ordinary-C TI binary also runs now and fails all 1,056 memory comparisons.

The initial investigation in commit `5549d9a` required a diagnostic two-call extension.
This follow-up replaces that extension with production support and execution tests.

## Target and behavior

The caller at `0xc0031840` calls `bitbuf_consume_bits` at `0xc0025e40`, then
`bitbuf_align_byte` at `0xc00269c0`, and clears the first context word. All arithmetic
and memory operations are integer operations. The three physical windows contain
176 bytes: 96 caller bytes, 32 consume bytes and 48 align bytes.

For a context with `consumed = ctx[0]`, `position = ctx[3]` and `remaining = ctx[4]`,
the independent oracle uses 32-bit wrapping arithmetic:

```text
remaining -= consumed
position += consumed
low = remaining & 7
if low != 0:
    remaining = (remaining & ~7) + 8
    position += low - 8
ctx[0] = 0
ctx[3] = position
ctx[4] = remaining
```

Both helpers issue two stores in their final return-delay packets. The second call
also begins while the caller's context-clear store is pending. The diagnostic trace
carries those effects through actual caller packets; it does not drain or restart the
pipeline at either call boundary. Live target/link checks observe exactly two call
entries, two helper returns and the original caller return.

## Production changes

The plural API accepts up to sixteen sequential calls to owned leaf windows. All plans
share the actual entry and endpoint. The scheduler carries the active invocation in
its state, so repeated calls to the same callee return to their own continuations.
Pending loads, stores, hazards and branch ages continue across each boundary.

Both calls here establish B3 before their final delay cycle. The proof now accepts an
early correct E1 link and tracks the complete six-advance delay window. It retains
unaffected constants across callees while conservatively invalidating possible callee
outputs and subsequent late register effects.

`CALLP.S2` in TI's ordinary-C wrapper now has an E1 B3 output and five implicit idle
advances. Full32/compact forms on both S units are supported; `.S1` uses A3. The link
points after the entire execute packet, including peers and fetch headers. Saved links
are tracked through exact register copies: the wrapper's `MV.L1X B3,A0` preserves the
original return link while CALLP overwrites B3, and `BNOP.S2X A0,5` returns through the
E1-captured A0 value. Clobbered, memory-derived or otherwise unproved saved links still
refuse, as do nested calls and invalid CALLP packets.

The new [call regressions](regressions.md) execute the formerly unsupported shapes in
both endians, including repeated callees and pending stores. The old single-call API
remains available. Cross-owner schedules remain read-only contracts, not function-body
merges or automatically installed decompiler overrides.

## Round-trip results

TI CGT C6000 8.3.15 compiled fresh trace-derived C with
`-mv6740 --abi=eabi --c99 -O2`, leaving compression enabled. The emitted function is
600 bytes in a 608-byte `.text` section, from 109 lines of recovered C. Type definitions
and explicit AMR read/clear/restore bindings make the emitted C compilable; its logic
was not rewritten by hand. The original is a void function; return PC, saved registers
and memory are checked, rather than inventing a return value.

| Variant | Boundary/random cases | AMR controls |
| --- | ---: | ---: |
| Original bytes, diagnostic two-call trace | 832 pass | 224 pass |
| Fresh trace-derived C, TI compiled | 832 pass | 224 pass |
| Deliberately corrupted output control | 832 detected | 224 detected |
| Ordinary-C TI binary | 832 memory mismatches | 224 memory mismatches |

The first corpus covers 12 boundary values each for consumed/remaining counts across
four context offsets, plus 256 seeded random cases. AMR controls vary seven unaffected
pointer modes, two modes per pointer and two BK pairs. The actual context addressing
mode stays linear. Each case checks the complete 4 KiB context arena against the
independent oracle, bounded private-stack writes, PC/B3, A10-A15/B10-B15 and AMR.
Both aligned and nonaligned bit counts exercise pending-store predicates. The native
caller restores B3; the ordinary-C binary returns through A0 and may leave its volatile
B3 holding an internal link. Its actual return PC and ABI-preserved registers are
checked without requiring that volatile B3 equal the return PC.

Ordinary decompilation still loses the first call's count load, the second call and the
final clear. Its first call uses an unresolved incoming B4; the C adapter exposes that
input as an explicit parameter. An unused incoming A11:A10 pair feeds only a dead
private C stack temporary and is bound to zero. No missing logic is repaired by hand.
The resulting 12-byte caller and scheduled helper compile and execute, confirming that
the remaining memory mismatch is a C-recovery failure rather than a CALLP refusal.

## Scope and retained evidence

The original and both callees retain their byte hashes and distinct owners. The only
scheduler used is the pinned production extension. For C export, a temporary payload
in the disposable project supplies that production trace to Ghidra's decompiler and is
restored afterward; it adds no scheduler semantics or call-model implementation.

The contract supports sequential, nonrecursive leaf calls. Callee link registers must
remain unchanged. Constant and saved-link proofs are conservative; this is not arbitrary
indirect-call, stack-value or nested-call support. The native trace has 46 states and
2,475 p-code operations, with two pending stores at each helper return and the caller's
clear store pending at the second callee entry.

These are bounded LE emulator results, not silicon validation or a portable-C
correctness proof. The recovered C includes signed arithmetic; matching TI output on
overflow cases does not prove freedom from C signed-overflow undefined behavior.

Local evidence is retained in the development checkout's ignored directory
`scratch/bitstream-flush-production-20261028/`: source/runtime hashes, unchanged image
hash, original and recovered C, TI assembly/ELFs, command receipts, production proof and
boundary metadata, behavioral summaries and witnesses, and an audit/evidence index.
`headless.py prepare`, `compile.py`, `headless.py compare` and `headless.py amr`, invoked
from that checkout, reproduce the run with its local image and pinned runtime. There
is no `probe` package in its script directory. Firmware bytes stay out of Git.

Verification passed all 112 `tools/verify.py --with-ti --jobs 2` release checks and
all seven Python release-tool tests. Per endian, the call fixtures execute 49 valid
schedules and check 54 unsafe or unsupported contracts. The retained audit confirms
that the production runtime and release-verification build have identical class bytes.
