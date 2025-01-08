#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  puts("Meow!");

  int f1 = 0;
  int f2 = 1;
  int f3 = f1 + f2;
  for (int i = 2; i < 18; i++) {
    f1 = f2;
    f2 = f3;
    f3 = f1 + f2;
  }

  printf("The eighteenth Fibonacci number is: %d\n", f3);
  return 0;
}
