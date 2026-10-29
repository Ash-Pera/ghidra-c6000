# Multiple-call integer round-trip experiment

On 2026-10-28, `bitstream_flush` and its two integer leaf helpers were tested from the
same DSP image as `codec_op_state_copy`. The production call model stopped at its
existing capability guards. A disposable diagnostic extension let the experiment
continue without changing firmware bytes or merging function owners. Its trace-derived
C compiled with TI and matched the original trace and an independent oracle in all
1,056 cases. This is experimental evidence, not production multiple-call support.

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

## Confirmed production limits

1. The single-call plan rejects the second call site as an undeclared control edge.
2. A bounded first-call-only plan independently refuses its valid early link. The
   first call issues at `0xc003184c`; MVK/MVKH establish B3 at `0xc0031860` /
   `0xc0031864`, followed by the final NOP delay advance at `0xc0031868`. The second
   call similarly finishes its link before its last delay cycle. The current contract
   requires the final link writer in the final delay cycle.
3. TI compiles the ordinary-C caller to a packet containing `MV.L1X B3,A0` and
   `CALLP.S2`. The scheduler refuses `CALLP.S2` with an unimplemented phase contract.
4. That rebuilt caller returns via `BNOP.S2X A0,5`. An isolated saved-link return
   independently refuses as an unresolved register branch; only B3 is recognized as a
   return target by the current scheduler.

The [closed-call fixture](regressions.md) now contains synthetic regressions for all
four observations in both endian modes. These are explicit expected refusals, not
assertions that valid firmware is erroneous. Relevant rules are SPRUFE8B 3.5, 3.7,
4.2.6 and the CALLP/B/BNOP/MVK/MVKH instruction descriptions.

Ordinary decompilation also loses the count load in the first call's delay window,
the second call and the final clear. Its remaining call uses an unresolved incoming B4
value. The source was compiled with explicit input/type bindings, but no behavioral
comparison of that TI binary is claimed: execution stops at the CALLP phase guard.

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
| Ordinary-C TI binary | CALLP refusal | CALLP refusal |

The first corpus covers 12 boundary values each for consumed/remaining counts across
four context offsets, plus 256 seeded random cases. AMR controls vary seven unaffected
pointer modes, two modes per pointer and two BK pairs. The actual context addressing
mode stays linear. Each case checks the complete 4 KiB context arena against the
independent oracle, bounded private-stack writes, PC/B3, A10-A15/B10-B15 and AMR.
Both aligned and nonaligned bit counts exercise pending-store predicates.

## Scope and retained evidence

The probe is a copy of the verified scheduler in a separate Java package, loaded only
in a disposable project. It adds two explicit, nonrecursive call edges to distinct
leaf callees, selects the corresponding return continuation and accepts an earlier
proved link. Each call destination and link is proved from its local constant-setup
prefix and checked from actual E1 snapshots during execution. The second prefix starts
after the first return; that helper has only pending stores, with no pending register
writes. This is a target-specific experiment, not a general interprocedural proof or a
nested/repeated-callee implementation. The installed extension is unchanged.

These are bounded LE emulator results, not silicon validation or a portable-C
correctness proof. The recovered C includes signed arithmetic; matching TI output on
overflow cases does not prove freedom from C signed-overflow undefined behavior.

Local evidence is retained in the development checkout's ignored directory
`scratch/bitstream-flush-multicall-20261028/`: runtime/source hashes, unchanged image
hash, `probe.patch`, ordinary and trace-derived C, TI assembly/ELFs, command receipts,
production refusals, native boundary metadata, behavioral summaries and witnesses, and
an audit/evidence index. `headless.py prepare`, `compile.py`, `headless.py compare` and
`headless.py amr`, invoked from that checkout, reproduce the experiment when its local
image and pinned runtime are available. Firmware bytes and the generated probe stay
out of Git.

The full `tools/verify.py --with-ti --jobs 2` run passed all 110 release checks,
including 50 closed-call/capability checks per endian. All seven Python release-tool
tests passed. The retained audit verifies the positive/negative outcomes, captured
call boundaries, compiled input hashes, unchanged image and installed runtime.
