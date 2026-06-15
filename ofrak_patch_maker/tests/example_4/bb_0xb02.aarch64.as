ldrh W0, [X7, #0xd0]
bl #0x13e0
ldrh W0, [X7, #0xd0]
bl #0x14d0
ldrh W3, [X7, #0xd0]
ldrb W3, [X3]
cmp X3, #0
beq #0xb20
