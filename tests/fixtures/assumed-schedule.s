; Own code (assumed-schedule.py): int pipe(const int *s, int n), n >= 5, sums n words; a one-packet loop that
; issues a branch to itself every cycle with loads in flight across the back edge.
        .text
        .global pipe, entered, branchy, plain, proved
pipe:   MV      .L1     A4,A5
||      ZERO    .S1     A4
||      SUB     .L2     B4,5,B0
  [B0]  B       .S2     loop
||[B0]  SUB     .L2     B0,1,B0
        LDW     .D1T1   *A5++,A3
||[B0]  B       .S2     loop
||[B0]  SUB     .L2     B0,1,B0
        LDW     .D1T1   *A5++,A3
||[B0]  B       .S2     loop
||[B0]  SUB     .L2     B0,1,B0
        LDW     .D1T1   *A5++,A3
||[B0]  B       .S2     loop
||[B0]  SUB     .L2     B0,1,B0
        MVK     .S1     1,A0
||      LDW     .D1T1   *A5++,A3
||[B0]  B       .S2     loop
||[B0]  SUB     .L2     B0,1,B0
loop:
  [A0]  SUB     .S1     A0,1,A0
||[!A0] ADD     .L1     A3,A4,A4
||[B0]  B       .S2     loop
||[B0]  SUB     .L2     B0,1,B0
||      LDW     .D1T1   *A5++,A3
        ADD     .L1     A3,A4,A4
        ADD     .L1     A3,A4,A4
        ADD     .L1     A3,A4,A4
        ADD     .L1     A3,A4,A4
        ADD     .L1     A3,A4,A4
        B       .S2     B3
        NOP     5
; Known-bad: plain returns 7, and entered is issued in its return's window.
        .align  32
plain:  B       .S2     B3
        MVK     .S1     7,A4
entered: MVK    .S1     9,A4
        NOP     3
; Known-bad: the entry packet holds a branch.
        .align  32
branchy: B      .S2     B3
||      MVK     .S1     3,A4
        NOP     5
; proved returns 5; the test records a review with its own evidence for it.
        .align  32
proved: MVK     .S1     5,A4
        B       .S2     B3
        NOP     5
