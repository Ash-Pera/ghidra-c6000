; Self-written C6000 source for parallel-read.py; constants there encode these words.
; samepkt:
;   MV .L1X B4,A4 || MV .L2X A4,B4
;   ADD .L1 A4,A4,A4
;   SUB .L1X A4,B4,A4
;   B .S2 B3
;   NOP 5
; Predicated writers:
;   [B0] MVK .S1 0x1234,A4 || [!B0] ADD .L1 1,A4,A4 || MV .L2X A4,B5
; Multi-cycle result:
;   MPY .M1 A2,A3,A4 || MV .L2X A4,B6
;   MV .L2X A4,B7
; Branch terminal:
; loop: [B1] ADD .L2 -1,B1,B1 || [B1] B loop
;   MV .L2 B1,B6
;   NOP 4
; Jump target:
;   B .S1 target+4
; target:
;   MV .L1X B4,A4 || MV .L2X A4,B4
