; SPDX-License-Identifier: Apache-2.0
; Three independent nested tail-call/return arms in one image (SPRUFE8B 3.5, 4.2.6 B).
; Arm A carries. Arm B is refused: an outside jump enters its delay window. Arm C is
; refused: its inner return guards on A1, not the owner's B0, so it is not proven false
; on the owner's taken path. Per-candidate carrying must still carry A while skipping B and C.
 .sect ".pf_two_nested_arms"
 .nocmp
 .global two_nested_arms
two_nested_arms:
afn:
 [B0] B.S1 TA
 [!B0] B.S2 FA
 NOP
 NOP
 NOP
 [B0] B.S2 B3
TA:
 NOP 5
 NOP 5
 NOP 5
 NOP 5
 NOP 5
 NOP 5
 .global FA
FA:
 B.S2 B3
 NOP 5
 .global bfn
bfn:
 [B0] B.S1 TB
 [!B0] B.S2 FB
 NOP
 NOP
BSLOT:
 NOP
 [B0] B.S2 B3
TB:
 NOP 5
 NOP 5
 NOP 5
 NOP 5
 NOP 5
 NOP 5
 .global FB
FB:
 B.S2 B3
 NOP 5
 .global enterb
enterb:
 B.S1 BSLOT
 NOP 5
 .global cfn
cfn:
 [B0] B.S1 TC
 [!B0] B.S2 FC
 NOP
 NOP
 NOP
 [A1] B.S2 B3
TC:
 NOP 5
 NOP 5
 NOP 5
 NOP 5
 NOP 5
 NOP 5
 .global FC
FC:
 B.S2 B3
 NOP 5
