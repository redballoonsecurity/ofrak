#include <stdio.h>

// Force no inline to demonstrate how main can be patched to call a different function
int __attribute__((noinline)) print_hello_world() {
    printf("Hello, World!\n");
    return 0;
}

int print_kitteh() {
    printf("kitteh! demands obedience...\n");
    return 0;
}

int main() {
   print_hello_world();
   return 0;
}
