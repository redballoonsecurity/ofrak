.syntax unified
.thumb
ldr r3, [r7, #0x14]
movs r2, #4
ldr r1, [pc, #0x20]
add r1, pc
mov r0, r3
blx #0x764
b #0x120e
