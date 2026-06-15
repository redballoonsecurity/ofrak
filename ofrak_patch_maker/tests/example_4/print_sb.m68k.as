link.w %A6, #0x0
lea.l (-8,%SP), %SP
move.l %D3, (%SP)
move.l %D4, (4,%SP)
move.l %D0, %D3

move.l #0, %D4

loop_start:

| print bratus line
move.l %D4, %D2
mulu #115, %D2
addi.l #0x400648ac, %D2
movea.l %D2, %A0
jsr 0x4004c934

| check if index within bounds of glasses
move.l %D4, %D2
sub.l %D3, %D2

cmpi.l #0, %D2
blt loop_cont

cmpi.l #5, %D2
bge loop_cont

| print go left line
movea.l #0x4003184c, %A0
jsr 0x4004c934

| print glasses line
move.l %D4, %D2
sub.l %D3, %D2
mulu #38, %D2
addi.l #0x4008ac2c, %D2
movea.l %D2, %A0
jsr 0x4004c934

loop_cont:

| print newline
movea.l #0x4004b4d8, %A0
jsr 0x4004c934

cmpi.l #45, %D4
jge exit

addi.l #1, %D4
bra loop_start

exit:
move.l (4,%SP), %D4
move.l (%SP), %D3
unlk %A6
rts
