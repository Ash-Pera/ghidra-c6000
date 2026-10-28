# Normal post-loop dispatch and missed stalls

The exact packet compiler models normal SPKERNEL exit using SPRUFE8B page 481 and
sections 7.9.4 and 7.12. This page defines the dispatch rule, hazard refusals and the
synthetic cases that exercise them.

## Dispatch rule

Post-loop instruction issue begins after `fstg * II + fcyc` drain advances, capped at
`dynlen - II`. No additional six-cycle frontend delay is added. General pipeline section
4.1.4 does not establish that the suspended sequential stream must be discarded. Abrupt
SPLOOPW exit retains its separate conservative transition contract; nested reload
remains unsupported.

The synthetic `II=6`, `dynlen=13`, count=3 case issues SPLOOP at cycle 0, loads source
cycles 1–13, reaches the last kernel boundary at 18 and starts draining at 19. With
delay 0, the first post-loop copy issues alongside a buffered B5 update and captures old
B5=1.

| Encoded delay | Effective drain delay | Next-packet marker cycle |
|---|---|---|
| 0 | 0 | 20 |
| 1 | 1 | 21 |
| 5 | 5 | 25 |
| 20 | 7, capped by `dynlen - II` | 27 |

Zero/one iterations retain padding through loading boundary 18. These expected cycles
are derived from the documented loop rule.

## Missed-stall refusals

SPRUFE8B sections 7.15.2, 7.16 and 7.17 specify missed-stall exceptions for buffered
X-path and AMR users. The compiler refuses a possible required missed stall; it does not
approximate exception state or add an ordinary global stall. Program-memory instructions
retain automatic stalls.

Opposite E1 predicates can exclude a hazard only when the sampled predicate value is
demonstrably unchanged. The hazard records that identity from all outputs committed
alongside its writer, including a final-phase output whose flight ends in that cycle.
External histories do not establish this identity. A late reader uses its earlier
captured predicate; current predicate facts cannot justify ignoring that hazard.
Ambiguous cases are refused.

## Constant suffix proof

The optional suffix proof decodes physical packets and builds an overapproximated
direct-control CFG, including preceding loop skip/backedges. The suffix entry must
dominate the loop. Bypass edges into the suffix, unresolved or out-of-scope targets,
incomplete delay boundaries and buffers not proved quiescent prevent the proof.

The interpreter starts with unknown registers and forgets values while incoming unknown
writes could mature. A successful proof removes impossible loading exits; it leaves loop
timing, arithmetic, unit checks and the pending-return contract intact.

## Synthetic regression

Generate both endian variants with TI's C6000 assembler:

```sh
python3 tests/fixtures/pipeline-postloop.py /tmp/postloop.bin /tmp/postloop.json
python3 tests/fixtures/pipeline-postloop.py /tmp/postloop-be.bin /tmp/postloop-be.json be
```

Set `TI_C6000_BIN` to the assembler's bin directory or `cl6x` executable. The default is
`/Applications/ti/ti-cgt-c6000_8.3.15/bin`. Generated assembly, objects and logs remain
beside the image. Ordinary instructions use `.nocmp`; invalid missed-stall cases use
documented raw loop words to bypass assembler scheduling checks.

Import at `0x1000` with the matching default C6000 language and run
`C6000PostLoopDispatchTest.java MANIFEST.json`. Require both endian modes to pass. The
separate `pipeline-loop.py` fixture exercises the normal-loop contract. Both are
available through the [release runner](verification.md).
