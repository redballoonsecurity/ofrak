SHELL := bash

CC = gcc
CFLAGS = -std=c99 \
	-pedantic \
	-Wall \
	-Wextra \
	-Werror \
	-fPIC \
	-fstack-protector-all \
	-D_FORTIFY_SOURCE=2 \
	-shared \
	-nostdlib \
	-O3
LDLIBS = -lm  # Link the math library

# Use this .so.1 extension because otherwise the dependency injector will
# erroneously try to import entropy.so, which will fail. 
entropy.so.1: entropy.c
	$(CC) \
		$(CFLAGS) \
		$(filter %.c, $^) \
		$(LDLIBS) \
		-o $@
