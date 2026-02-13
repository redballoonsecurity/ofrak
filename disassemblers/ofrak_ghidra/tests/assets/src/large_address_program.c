int foo(int x, int y) {
    switch (x) {
        case 1:
            return y + 2;
        case 2:
            return y * 2;
        case 3:
            return y * y;
        default:
            return x + y;
    }
}

void _start(void) {
    int result = foo(5, 3);
    __asm__ volatile(
        "mov $60, %%rax\n"
        "mov %0, %%rdi\n"
        "syscall\n"
        :: "r"((long)result) : "rax", "rdi"
    );
}
