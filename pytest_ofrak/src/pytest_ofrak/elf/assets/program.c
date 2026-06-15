
#include <stdio.h>

int foo();
int bar();

int main() {
   printf("Hello, World!\n");
   return foo();
}

int foo() {
    return 12;
}

int bar() {
    return 24;
}
