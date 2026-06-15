/* Place .text at 0x80000000 to test large address handling */
SECTIONS {
    . = 0x80000000;
    .text : { *(.text*) }
}
