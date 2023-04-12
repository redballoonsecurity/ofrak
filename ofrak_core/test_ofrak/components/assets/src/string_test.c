#include <stdio.h>

extern int longString(void);
extern int shortString(void);

// Generate bytes that look like a long ascii string (21 bytes)
__asm__(".global longString\n\t"
		".type longString, @function\n\t"
		"push %r15\n\t"
		"push %r15\n\t"
		"push %r15\n\t"
		"push %r15\n\t"
		"push %r15\n\t"
		"push %r15\n\t"
		"push %r15\n\t"
		"push %r15\n\t"
		"and 0, %r15\n\t"
);

// Generate bytes that look like a short ascii string (7 bytes)
__asm__(".global shortString\n\t"
		".type shortString, @function\n\t"
		"push %r15\n\t"
		"and 0, %r15\n\t"
);

int main() {
	printf("O");
	printf("h, hi");
	printf(" Mark!\n");
	printf("You are tearing me apart, Lisa!\n");
	return 0;
}
