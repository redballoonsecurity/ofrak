/*
 * A minimal bare-metal Cortex-M style program for the referenced strings tests: code and
 * constants in flash at 0x08000000, as on STM32 microcontrollers, variables in SRAM at 0x20000000
 * and above.
 *
 * At -O2, both functions load an address from a literal pool in flash: `boot` the address of its
 * string literal, which it passes to `report`, and `report` the address of `last_message` (a .bss
 * variable). `last_message` is placed at an address whose low bytes are printable characters, so
 * that the literal pool word holding it reads like a short string ("@A"), as the addresses of RAM
 * variables do in firmware: it must not be taken for a string `report` references.
 *
 * Built with gcc-arm-linux-gnueabi 15.2.0-16ubuntu1 (Ubuntu), as fw-cortex-m.elf (`-n` keeps the
 * ELF headers out of the flash image, as firmware linker scripts do):
 *   arm-linux-gnueabi-gcc -O2 -mcpu=cortex-m3 -mthumb -ffreestanding -fno-pic -nostdlib \
 *       -nostartfiles -static -Wl,--build-id=none -Wl,-n -Wl,-e,boot -Wl,-Ttext=0x08000000 \
 *       -Wl,-Tbss=0x20004140 -o fw-cortex-m.elf fw-cortex-m.c
 */
const char *volatile last_message;

/* A logging function, called rather than inlined, as firmware's usually are */
__attribute__((noinline)) void report(const char *message)
{
    last_message = message;
}

void boot(void)
{
    report("Image signature invalid");
    for (;;) {
    }
}
