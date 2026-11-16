; SPDX-License-Identifier: Apache-2.0
 .sect ".pf_nested_return_arm"
 .nocmp
 .global nested_return_arm
nested_return_arm:
 [B0] B.S1 T
 [!B0] B.S2 F
 NOP
 NOP
 NOP
 [B0] B.S2 B3
T:
 NOP 5
 NOP 5
 NOP 5
 NOP 5
 NOP 5
 NOP 5
 .global F
F:
 B.S2 B3
 NOP 5
