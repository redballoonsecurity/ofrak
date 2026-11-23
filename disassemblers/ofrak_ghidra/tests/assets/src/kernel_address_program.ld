/* Place .text in the upper half of the 64-bit address space, where addresses are negative as signed 64-bit integers */
SECTIONS {
    . = 0xffffffff80000000;
    .text : { *(.text*) }
}
