/*
 * `load_literal` reads from the literal pool emitted right after it, so the function owns a data
 * word that is referenced from code.
 */
__asm__(
    ".text\n"
    ".global load_literal\n"
    ".type load_literal, %function\n"
    "load_literal:\n"
    "    ldr x0, =0x1122334455667788\n"
    "    ret\n"
    "    .ltorg\n"
);

unsigned long load_literal(void);

void _start(void) {
    load_literal();
    while (1) {}
}
