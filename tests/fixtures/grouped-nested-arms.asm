; SPDX-License-Identifier: Apache-2.0
; A two-level nested-arm chain: the inner transfer of arm0 is itself the owner of arm1, so
; arm0 and arm1 share the carrier at the inner owner's last slot. arm1 is refused because
; dent jumps into its window. Because the two candidates share a carrier they must be skipped
; together: carrying arm0 alone (a partial-group accept) would be wrong. Correct carrying
; skips the whole group, so arm0's owner keeps its branch and its carrier takes no call.
 .sect ".pf_grouped_nested_arms"
 .nocmp
 .global grouped_nested_arms
grouped_nested_arms:
 [!B0] B.S2 GD
 NOP
 NOP
 [B0] B.S2 B3
 NOP
 NOP
DSLOT:
 NOP
 [!B0] B.S2 B3
 NOP
 NOP
 NOP
 NOP
 NOP
 NOP
 .global GD
GD:
 B.S2 B3
 NOP 5
 .global dent
dent:
 B.S1 DSLOT
 NOP 5
