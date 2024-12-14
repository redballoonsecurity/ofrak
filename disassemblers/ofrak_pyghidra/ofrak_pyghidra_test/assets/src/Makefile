# Will only work in Docker, not macOS
CC = /opt/rbs/toolchain/gcc-arm-none-eabi-10-2020-q4-major/bin/arm-none-eabi-gcc

# From: https://stackoverflow.com/a/23922211
CFLAGS = --specs=nosys.specs

all: ../fib ../fib_thumb

../fib: fib
	mv fib ..

../fib_thumb: fib_thumb
	mv fib_thumb ..

fib: fib.c

fib_thumb: fib.c
	$(CC) $(CFLAGS) -mthumb -o $@ $<
