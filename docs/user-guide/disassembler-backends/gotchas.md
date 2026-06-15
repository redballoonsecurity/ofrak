# Gotchas

## Position Independent Executables (PIE)

In order to extract complex blocks, basic blocks, and instructions from PIE files, OFRAK changes the virtual address of `CodeRegion`s unpacked from the file format to match the virtual address used by the backend (Ghidra, Angr, etc.)

This is because different backends load PIE files at different virtual addresses. For example Ghidra loads them at `0x10000` whereas Angr loads them at `0x400000`. However, for file formats such as ELF, the virtual address taken from the header is `0x0`.

Therefore, when analyzing/modifying PIE files, addresses used should be those from the backend you are using. This also lowers friction when developing an OFRAK script in parallel with manual analysis in the backend of your choice.

<div align="right">
<img src="../../assets/square_02.png" width="125" height="125">
</div>
