# Gotchas

## PIE

In order to extract complex blocks, basic blocks, and instructions from position-idependent executables (PIE), OFRAK changes the virtual address of `CodeRegion`'s unpacked from the file format to match the virtual address used by the backend (Ghidra, Angr, etc.)

This is because different backends load PIE files at different virtual addresses. For example Ghdira loads them at `0x10000` whereas Angr loads the mat `0x400000`. However, for file formats such as ELF, the virtual address taken from the header is `0x0`.

Therefore, when analyzing/modifying PIE files, addresses used should be those from the backend you are using. This also lowers friction when developing an OFRAK script in parallel with manual analysis in the backend of your choice.
