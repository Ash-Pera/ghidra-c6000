; link-jump fixture (hand-written, firmware-free)
        .text
        .global h, g, ljloop, ljonly, ljwrite, ljbusy, ljpred, ljclob
h:      B       .S2     B3
        ADD     .L1     A4,A4,A4
        NOP     4
        .align  32
g:      B       .S2     B3
        ADD     .L1     A4,3,A4
        NOP     4
        .align  32
; n ? 2v + 3(n-1) : g(v), the jump to g a loop call or a tail call by path
ljloop: MV      .L2     B3,B6
||      MV      .L1X    B4,A2
  [!A2] B       .S1     ll_top
        NOP     5
        MVKL    .S2     ll_top,B3
        MVKH    .S2     ll_top,B3
        B       .S1     h
        NOP     5
ll_top: SUB     .L1     A2,1,A2
  [A2]  B       .S1     g
  [!A2] MV      .L2     B6,B3
        NOP     4
        B       .S2     B3
        NOP     5
        .align  32
; the link is always the loop head: v + 3n for n >= 1
ljonly: MV      .L2     B3,B6
||      MV      .L1X    B4,A2
        MVKL    .S2     lo_top,B3
        MVKH    .S2     lo_top,B3
lo_top: SUB     .L1     A2,1,A2
  [A2]  B       .S1     g
  [!A2] MV      .L2     B6,B3
        NOP     4
        B       .S2     B3
        NOP     5
        .align  32
; known-bad: the window builds the link past it, an ordinary call
ljwrite: MV     .L2     B3,B6
||      MV      .L1X    B4,A2
        MVKL    .S2     lw_top,B3
        MVKH    .S2     lw_top,B3
lw_top: SUB     .L1     A2,1,A2
  [A2]  B       .S1     g
  [A2]  MVKL    .S2     lw_ret,B3
  [A2]  MVKH    .S2     lw_ret,B3
  [!A2] MV      .L2     B6,B3
        NOP     3
lw_ret: B       .S2     B6
        NOP     5
        .align  32
; known-bad: another transfer in the window
ljbusy: MV      .L2     B3,B6
||      MV      .L1X    B4,A2
        MVKL    .S2     lb_top,B3
        MVKH    .S2     lb_top,B3
lb_top: SUB     .L1     A2,1,A2
  [A2]  B       .S1     g
  [!A2] B       .S2     B6
        NOP     4
        NOP     5
        .align  32
; known-bad: the window rewrites the jump's predicate (issue #66)
ljpred: MV      .L2     B3,B6
||      MV      .L1X    B4,A2
        MVKL    .S2     lp_top,B3
        MVKH    .S2     lp_top,B3
lp_top:
  [A2]  B       .S1     g
  [A2]  SUB     .L1     A2,1,A2
        NOP     4
        B       .S2     B6
        NOP     5
        .align  32
; known-bad: the loop rewrites the link before the jump
ljclob: MV      .L2     B3,B6
||      MV      .L1X    B4,A2
        MVKL    .S2     lc_top,B3
        MVKH    .S2     lc_top,B3
lc_top: SUB     .L1     A2,1,A2
        MV      .L2     B6,B3
  [A2]  B       .S1     g
        NOP     5
        B       .S2     B3
        NOP     5
