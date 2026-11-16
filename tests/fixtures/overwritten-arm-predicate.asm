; SPDX-License-Identifier: Apache-2.0
; A return [B1] B B3 issues [A1] B B3 in its window. A1 is first rewritten there under [!A1], then
; cleared under [B1], so the inner return is false whenever the outer is taken (SPRUFE8B 3.5, 4.2.6 B).
; The inner return's window issues [!A1] B BLK, a jump within the function.
; int f(int *p, int q): p[4] ? (p[4]--, 1) : (q == 0 || g4 >= 0 || g2 > 1) ? 0 : (g2 = 2, 9)
 .sect ".pf_overwritten_arm"
 .nocmp
 .global pend
pend:
 MVK.S2 0x100,B7
 B.S2 T1
|| LDW.D1T2 *+A4[4],B1
|| LDW.D2T1 *+B7[4],A2
 LDW.D2T1 *+B7[2],A0
 CMPEQ.L1X 0,B4,A1
 NOP 2
 [B1] B.S2 B3
|| [!A1] CMPLT.L1 -1,A2,A1
T1:
 [B1] SUB.D2 B1,1,B0
|| [!A1] CMPLT.L1 1,A0,A1
 [B1] ZERO.D1 A1
 [A1] B.S2 B3
 [B1] STW.D1T2 B0,*+A4[4]
|| [B1] MVK.S1 1,A4
 [A1] ZERO.D1 A4
 [!A1] B.S2 BLK
 NOP 2
 MVK.S1 2,A0
 STW.D2T1 A0,*+B7[2]
 NOP
 NOP
 NOP
BLK:
 MVK.S1 9,A4
 B.S2 B3
 NOP 5

; Refused: the clearing write's guard B0 is not implied by the owner's B1.
 .sect ".pf_bad_unimplied"
 .nocmp
 .global bad_unimplied
bad_unimplied:
 MVK.S2 0x100,B7
 LDW.D1T2 *+A4[4],B1
 LDW.D2T1 *+B7[4],A2
 LDW.D2T1 *+B7[2],A0
 CMPEQ.L1X 0,B4,A1
 NOP 2
 [B1] B.S2 B3
|| [!A1] CMPLT.L1 -1,A2,A1
 [B1] SUB.D2 B1,1,B0
 [B0] ZERO.D1 A1
 [A1] B.S2 B3
 NOP 5

; Refused: after the clearing write, an [A0] write to A1 may run when the owner is taken.
 .sect ".pf_bad_later_write"
 .nocmp
 .global bad_later_write
bad_later_write:
 MVK.S2 0x100,B7
 LDW.D1T2 *+A4[4],B1
 LDW.D2T1 *+B7[4],A2
 LDW.D2T1 *+B7[2],A0
 CMPEQ.L1X 0,B4,A1
 NOP 2
 [B1] B.S2 B3
|| [!A1] CMPLT.L1 -1,A2,A1
 [B1] ZERO.D1 A1
 [A0] MVK.S1 1,A1
 [A1] B.S2 B3
 NOP 5

; Refused: an unpredicated MVK follows the in-function jump inside the inner return's window.
 .sect ".pf_bad_non_nop_tail"
 .nocmp
 .global bad_non_nop_tail
bad_non_nop_tail:
 MVK.S2 0x100,B7
 B.S2 T_BAD_NON_NOP
|| LDW.D1T2 *+A4[4],B1
|| LDW.D2T1 *+B7[4],A2
 LDW.D2T1 *+B7[2],A0
 CMPEQ.L1X 0,B4,A1
 NOP 2
 [B1] B.S2 B3
|| [!A1] CMPLT.L1 -1,A2,A1
T_BAD_NON_NOP:
 [B1] SUB.D2 B1,1,B0
|| [!A1] CMPLT.L1 1,A0,A1
 [B1] ZERO.D1 A1
 [A1] B.S2 B3
 [B1] STW.D1T2 B0,*+A4[4]
|| [B1] MVK.S1 1,A4
 [A1] ZERO.D1 A4
 [!A1] B.S2 BLK_BAD_NON_NOP
 MVK.S1 2,A0
 NOP
 STW.D2T1 A0,*+B7[2]
 NOP
 NOP
 NOP
BLK_BAD_NON_NOP:
 MVK.S1 9,A4
 B.S2 B3
 NOP 5

; Refused: the in-function jump is not first in its execute packet.
 .sect ".pf_bad_first_packet"
 .nocmp
 .global bad_first_packet
bad_first_packet:
 MVK.S2 0x100,B7
 B.S2 T_BAD_FIRST_PACKET
|| LDW.D1T2 *+A4[4],B1
|| LDW.D2T1 *+B7[4],A2
 LDW.D2T1 *+B7[2],A0
 CMPEQ.L1X 0,B4,A1
 NOP 2
 [B1] B.S2 B3
|| [!A1] CMPLT.L1 -1,A2,A1
T_BAD_FIRST_PACKET:
 [B1] SUB.D2 B1,1,B0
|| [!A1] CMPLT.L1 1,A0,A1
 [B1] ZERO.D1 A1
 [A1] B.S2 B3
 [B1] STW.D1T2 B0,*+A4[4]
|| [B1] MVK.S1 1,A4
 [A1] ZERO.D1 A4
 [A0] MVK.S1 2,A0
|| [!A1] B.S2 BLK_BAD_FIRST_PACKET
 NOP 2
 MVK.S1 2,A0
 STW.D2T1 A0,*+B7[2]
 NOP
 NOP
 NOP
BLK_BAD_FIRST_PACKET:
 MVK.S1 9,A4
 B.S2 B3
 NOP 5

; Refused: a second transfer, [!A1] B B0, issues in the inner return's window; BLK is not where sequential issue lands.
 .sect ".pf_bad_extra_jump"
 .nocmp
 .global bad_extra_jump
bad_extra_jump:
 MVK.S2 0x100,B7
 B.S2 T_BAD_EXTRA_JUMP
|| LDW.D1T2 *+A4[4],B1
|| LDW.D2T1 *+B7[4],A2
 LDW.D2T1 *+B7[2],A0
 CMPEQ.L1X 0,B4,A1
 NOP 2
 [B1] B.S2 B3
|| [!A1] CMPLT.L1 -1,A2,A1
T_BAD_EXTRA_JUMP:
 [B1] SUB.D2 B1,1,B0
|| [!A1] CMPLT.L1 1,A0,A1
 [B1] ZERO.D1 A1
 [A1] B.S2 B3
 [B1] STW.D1T2 B0,*+A4[4]
|| [B1] MVK.S1 1,A4
 [A1] ZERO.D1 A4
 [!A1] B.S2 BLK_BAD_EXTRA_JUMP
 [!A1] B.S2 B0
 NOP
 MVK.S1 2,A0
 STW.D2T1 A0,*+B7[2]
 NOP
 NOP
 NOP
BLK_BAD_EXTRA_JUMP:
 MVK.S1 9,A4
 B.S2 B3
 NOP 5

; Refused: an issue peer of the owner rewrites the link B3 the inner return reads.
 .sect ".pf_bad_peer_link"
 .nocmp
 .global bad_peer_link
bad_peer_link:
 MVK.S2 0x100,B7
 LDW.D1T2 *+A4[4],B1
 LDW.D2T1 *+B7[4],A2
 LDW.D2T1 *+B7[2],A0
 CMPEQ.L1X 0,B4,A1
 NOP 2
 [B1] B.S2 B3
|| [!A1] CMPLT.L1 -1,A2,A1
|| MV.L2 B5,B3
 [B1] ZERO.D1 A1
 NOP
 [A1] B.S2 B3
 NOP 5
