ldr X3, [X7, #4]
mov X2, #0
strb W2, [X3, #2]
ldr X3, [X7, #4]
ldrb W2, [X3, #2]
ldr X3, [X7, #4]
strb W2, [X3, #1]
ldr X3, [X7, #4]
ldrb W3, [X3, #9]
cmp X3, #0
bne #0x1324
