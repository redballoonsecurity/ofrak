.syntax unified
.thumb
push {r7}
sub sp, #0x14
add r7, sp, #0
str r0, [r7, #4]
str r1, [r7]
ldr r3, [r7]
ldrb r3, [r3, #5]
strb r3, [r7, #0xf]
ldr r3, [r7, #4]
adds r3, #3
ldrb r3, [r3]
uxth r3, r3
lsls r3, r3, #8
uxth r2, r3
ldr r3, [r7, #4]
adds r3, #2
ldrb r3, [r3]
uxth r3, r3
add r3, r2
strh r3, [r7, #0xc]
ldr r3, [r7, #4]
adds r3, #4
ldrb r3, [r3]
asrs r3, r3, #2
uxtb r3, r3
and r3, r3, #3
strb r3, [r7, #0xb]
ldrb r3, [r7, #0xb]
cmp r3, #0
ite ne
movne r3, #1
moveq r3, #0
uxtb r3, r3
mov r2, r3
ldr r3, [r7]
strb r2, [r3, #5]
ldr r3, [r7]
ldrb r3, [r3, #5]
cmp r3, #0
beq #0xd2c
