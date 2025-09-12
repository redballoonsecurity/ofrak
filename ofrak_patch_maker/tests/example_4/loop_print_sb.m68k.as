move.l #0, %D3

loop_start:

move.l %D3, %D0
jsr 0x401248d0

cmpi #18, %D3
bge loop_cont

movea.l #0x4005b6e4, %A0
jsr 0x4004c934

loop_cont:
addi.l #1, %D3
cmpi #19, %D3
blt loop_start

rts
