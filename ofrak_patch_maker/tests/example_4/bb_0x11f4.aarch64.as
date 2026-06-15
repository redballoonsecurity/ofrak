ldr X3, [X7, #0x14]
mov X2, #4
ldr X1, .+0x20
adr X0, .
add X1, X1, X0
mov X0, X3
bl #0x764
b #0x1210
