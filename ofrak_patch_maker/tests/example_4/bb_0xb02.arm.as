.syntax unified
.thumb
ldr.w r0, [r7, #0xd0]
bl #0x13e0
ldr.w r0, [r7, #0xd0]
bl #0x14d0
ldr.w r3, [r7, #0xd0]
ldrb r3, [r3]
cmp r3, #0
beq #0xb20
