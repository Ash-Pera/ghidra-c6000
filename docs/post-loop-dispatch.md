# Normal post-loop dispatch and missed stalls

The exact issue model follows SPRUFE8B SPKERNEL p.481, 7.9.4 and 7.12:
post-loop instruction execution begins after fstg*II+fcyc drain advances, capped
at dynlen-II. There is no extra six-cycle E1 delay. General pipeline section
4.1.4 alone does not require discarding a suspended sequential frontend. This
corrects the previous model inference; agreement with an emulator sharing the
same inference was not independent evidence. Abrupt SPLOOPW transitions retain
their separate existing contract. Reloads remain unsupported.

For the public II6/dynlen13/count3 fixture, SPLOOP executes at cycle0; body
cycles1..13 load the source, the last kernel boundary is18, and draining starts19.
With delay0 the first post-loop copy issues at19, simultaneously with a buffered
B5 update; it captures old B5=1. A marker in the next packet commits at20.
Delays1/5 move that marker to21/25. Delay20 caps at7, producing marker27 after
buffer idle. Zero/one iterations retain padding through loading boundary18.
These expectations come from the manual, not an emulator output. The previous
model fails the delay0 case with47 total advances instead of41. Existing loop
assertions have not been changed to fit the implementation.

SPRUFE8B 7.15.2, 7.16 and 7.17 specify missed-stall exceptions for buffered
X-path/AMR users. The compiler refuses a possible required missed stall rather
than inventing a global stall or approximating exception state. PM users keep
automatic stalls. Opposite E1 predicates are accepted only when their sampled
predicate value is demonstrably unchanged. Each hazard records this identity
from all outputs committed alongside the writer, including a final-phase output
whose flight disappears at the end of that cycle. Legacy/external histories do
not establish identity. A late reader already captured its
predicate in an earlier cycle: current predicate facts do not justify ignoring
its hazard. Ambiguous cases are conservatively refused.

The optional constant suffix proof reads raw decoded packets and constructs an
overapproximate direct-control CFG, including earlier loop skip/backedges. It
requires the suffix entry to dominate the loop and refuses bypass edges into
the suffix, unresolved targets, out-of-scope edges, incomplete branch-delay
boundaries, and earlier buffers not proved quiescent. It starts with unknown
registers and forgets knowledge while incoming unknown writes could mature,
then uses the existing integer constant interpreter. It proves impossible
loading exits; it does not rewrite loop cycles, arithmetic, unit checks or the
pending-return contract.

Generate stock-free fixtures with:

```
python3 tests/fixtures/pipeline-postloop.py /tmp/postloop.bin /tmp/postloop.json
python3 tests/fixtures/pipeline-postloop.py /tmp/postloop-be.bin /tmp/postloop-be.json be
```

TI_C6000_BIN selects the TI assembler bin directory or cl6x executable, default
/Applications/ti/ti-cgt-c6000_8.3.15/bin. Source, object and logs stay beside the
image. Ordinary instructions are assembled with .nocmp; deliberately invalid
missed-stall cases use documented raw loop-control words to bypass assembler
scheduling checks, with the ordinary instruction semantics unchanged. Import
at0x1000 in the matching C6000 endian language and run
C6000PostLoopDispatchTest.java MANIFEST.json. Both endians must pass. The
separate49-case pipeline-loop.py consumer remains applicable unchanged.
