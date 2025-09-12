.syntax unified
.thumb
blx #0x734
mov r2, r0
ldr r3, [r7, #4]
str r2, [r3, #0xc]
ldr r3, [r7, #4]
ldrb r3, [r3, #1]
cmp r3, #0
ite eq
moveq r3, #1
movne r3, #0
uxtb r3, r3
ldr r3, [r7, #4]
strb r2, [r3, #2]
ldr r3, [r7, #4]
ldrb r2, [r3, #2]
ldr r3, [r7, #4]
strb r2, [r3, #1]
ldr r3, [r7, #4]
ldrb r3, [r3, #7]
adds r3, #1
uxtb r2, r3
ldr r3, [r7, #4]
strb r2, [r3, #7]
ldr r3, [r7, #4]
ldrb r3, [r3, #7]
cmp r3, #4
bls #0x13ce
