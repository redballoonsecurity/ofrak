.syntax unified
.thumb
ldr r3, [r7, #4]
movs r2, #0
strb r2, [r3, #2]
ldr r3, [r7, #4]
ldrb r2, [r3, #2]
ldr r3, [r7, #4]
strb r2, [r3, #1]
ldr r3, [r7, #4]
ldrb r3, [r3, #9]
cmp r3, #0
bne #0x1324
