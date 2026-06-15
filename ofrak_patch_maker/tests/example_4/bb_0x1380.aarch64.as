bl #0x734
mov X2, X0
ldr X3, [X7, #4]
str X2, [X3, #0xc]
ldr X3, [X7, #4]
ldrb W3, [X3, #1]
cmp X3, #0
mov X3, #1
mov X3, #0
uxtb W3, W3
ldr X3, [X7, #4]
strb W2, [X3, #2]
ldr X3, [X7, #4]
ldrb W2, [X3, #2]
ldr X3, [X7, #4]
strb W2, [X3, #1]
ldr X3, [X7, #4]
ldrb W3, [X3, #7]
add X3, X3, #1
uxtb W2, W3
ldr X3, [X7, #4]
strb W2, [X3, #7]
ldr X3, [X7, #4]
ldrb W3, [X3, #7]
ldrb W3, [X3, #7]
cmp X3, #4
bls #0x13d0
