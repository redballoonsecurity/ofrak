str X7, [SP]
sub sp, sp, #0x14
add X7, sp, #0
str X0, [X7, #4]
str X1, [X7]
ldr X3, [X7]
ldrb W3, [X3, #5]
strb W3, [X7, #0xf]
ldr X3, [X7, #4]
adds X3, X3,  #3
ldrb W3, [X3]
uxth W3, W3
lsl X3, X3, #8
uxth W2, W3
ldr X3, [X7, #4]
adds X3, X3, #2
ldrb W3, [X3]
uxth W3, W3
add X3, X3, X2
strh W3, [X7, #0xc]
ldr X3, [X7, #4]
adds X3, X3, #4
ldrb W3, [X3]
asr X3, X3, #2
uxtb W3, W3
and X3, X3, #3
strb W3, [X7, #0xb]
ldrb W3, [X7, #0xb]
cmp X3, #0
mov X3, #0  //aarch64 does not have conditional instructions
mov X3, #1
uxtb W3, W3
mov X2, X3
ldr X3, [X7]
strb W2, [X3, #5]
ldr X3, [X7]
ldrb W3, [X3, #5]
cmp X3, #0
beq #0xd2c
