#!/bin/bash

SRC="int main(){return 0;}"
OUT="kernel_address_space.out"

echo "$SRC" | gcc -xc -std=c99 -nostdlib -Og -fno-pic -no-pie -mcmodel=kernel -maddress-mode=long -Wl,--section-start=.text=0xffffffff80000000 - -o "$OUT"
