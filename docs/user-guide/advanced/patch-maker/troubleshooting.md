# PatchMaker troubleshooting guide
The PatchMaker is a powerful tool that can be used to inject code in an existing binary, using
assembly or C source code. The PatchMaker uses a selected toolchain to compile/assemble source
code/assembly into bytes, to be injected in the target binary.

During this process, it is possible to encounter assembler/compiler/linker errors in the
corresponding OFRAK log. This troubleshooting guide describes common errors and how to address them.

## Missing function definition and symbol
Error:
```
/path/to/linker-ld: /path/to/obj_file.c.o: in function `function_name':
/path/to/source.c:39: undefined reference to `printf'
```
This means that a function that is used in the C code is not defined. To resolve this, a user needs
to:

- find the address of that function in the binary, for example through reverse engineering
- define the function's prototype, for example: `extern void printf(const char *restrict format, ...);`
- define a symbol for the function, then pass it to the PatchMaker in the `base_symbols` field, for example like this: `patch_maker = PatchMaker([...], base_symbols=["printf": 0x1234],)`

## Missing compiler builtins or libraries
Users might want to use math operators in C code, like divide or modulo operators, which may rely
on compiler builtins. Users might also want to use commonly used standard functions which come from
libraries.

In this section we take the example of math operators.

Error:
```
/path/to/linker-ld: /path/to/obj_file.c.o: in function `function_name':
/path/to/source.c:14: undefined reference to `__aeabi_uidivmod'
```
Examples of builtins under this category are `__aeabi_uidivmod` or `__aeabi_idivmod` if compiling
with GCC or `__umodsi3` if compiling with Clang.

To address this, find the function in the binary and define a symbol for it, then pass it to the PatchMaker in the `base_symbols` field. Note that in the math operators case, there is no need to define the function's prototype like in the above section, as those types of functions are compiler builtins.

Note that the PatchMaker implementation doesn't yet allow linking against libraries.

## Multiple symbol definitions
Error:
```
/path/to/linker-ld: /path/to/obj_file.c.o: in function `function_name':
(.text+0x0): multiple definition of `function_name'; /path/to/obj_file.c.o:/path/to/source.c:26: first defined here
```
This issue occurs when a symbol is defined more than once. This usually happens when a function or
variable is defined in the source, and is also provided as symbol to the PatchMaker, in the
`base_symbols` field. In case such as these, the symbol should only be defined in the source, and
not passed to the PatchMaker.

## Patch doesn't fit in patch range
Error:
```
/path/to/linker-ld: address 0xabcd of /path/to/FEM_executable section `.rbs_function_name_text' is not within region `.rbs_function_name_text_mem'
# or:
/path/to/linker-ld: /path/to/FEM_executable section `.text' will not fit in region `.rbs_name_text_mem'
# or:
/path/to/linker-ld: region `.region_name_text_mem' overflowed by 2 bytes
```
This issue occurs when the patch that is compiled/assembled is larger in byte size compared to the
space defined in the segment it is going to be inject in (which is part of the `segments` field of
the `PatchRegionConfig`).

There are three approaches for addressing this:

- if it's not already the case, use `CompilerOptimizationLevel.SPACE,` for the `compiler_optimization_level` field of the `ToolchainConfig`.
- create a bigger segment for the patch, if additional space is available
- consider extending the binary to make as much space as needed for the patch. An example is OFRAK [example 7](../../../examples/ex7_code_insertion_with_extension.html).

## Use of read-only data
Error:
```
/path/to/linker-ld: /path/to/FEM_executable section `.rodata' will not fit in region `.rbs_region_name_text_mem'
```
This issue occurs when read-only data is used in the patch code, but a destination segment for those
data is not defined.

A common case for this is using strings. If the target string is already available in the binary,
consider using a pointer to it instead of re-defining the string. The string can be defined like
this: `extern char string1;`, and then used like this: `printf (&string1);`. Finally, a symbol must be
defined for it and passed to the `PatchMaker` in the `base_symbols` field.

Alternatively, a read-only segment part of the `segments` field of the `PatchRegionConfig` can be
defined. Note that additional space will be required for that segment.

## Use of global variables
Error:
```
ofrak_patch_maker.model.PatchMakerException: .bss found but `no_bss_section` is set in the provided ToolchainConfig!
```
This issue occurs when the `no_bss_section=True` is set in the `ToolchainConfig`, but the code still
employs uninitialized data. This is usually a result of one or more uninitialized global variable.

If that global variable was already present in the binary and needs to be reused it, a user can
find its address, provide it as a symbol to the `PatchMaker` in the `base_symbols` field, and define
it in the C code as extern: `extern uint8_t variable_name;`.

Alternatively, a `.bss` segment can be defined, and passed to `make_fem` in the `unsafe_bss_segment`
argument. Note that additional space will be required for that segment.

Another error can be:
```
/path/to/linker-ld: warning: start of section .igot.plt changed by 1
/path/to/linker-ld: /path/to/FEM_executable section `.data' will not fit in region `.rbs_region_name_data_mem'
```
In this case the data is initialized and needs to reside in a `.data` readable and writable (RW)
section. There are two approaches for addressing this:

- reuse the variable in the binary, if present, as described above.
- define a read-write segment part of the `segments` field of the `PatchRegionConfig`. Note that additional space will be required for that segment.

## Linking to existing global variables in the target binary
Error:
```
/path/to/linker-ld: error: no memory region specified for section '.rel.dyn'
```
This issue occurs when the patch uses a global variable in the target binary, so the linker attempts to link the usages in the patch to the address in the target binary.
Linkers often try to do this with a Global Offset Table, a table of pointers which gets put in the `.got` section, and the offsets of those pointers are stored in the `.rel.dyn` section.
The code using the variable is expected to load an address from an offset in this table, and the dynamic linker is expected to fix up this table at runtime to have accurate pointers.
When injecting a patch, we usually don't want to have to deal with a Global Offset Table since, in the best-case scenario, it would mean finding and appending to the table already in the target binary, which is complicated.

A good workaround is to use `__attribute__((weak))` instead of `extern` when declaring the global variable in the patch source code, and defining a strong symbol for the variable at the address in the target binary.
Contrary to `extern`, declaring a symbol as "weak" will count as a definition so that the BOM can be built without a Global Offset Table to resolve the pointer to some outside data.
But, since a "weak" definition can still be overruled by a "strong" definition of the variable elsewhere, you can define the variable at the correct address when building the FEM and the linker will go fix the usage of that variable to point at the correct address.
If using the symbol stub generation provided by OFRAK's `LinkableBinary` (indirectly in `PatchFromSourceModifier` or `FunctionReplacementModifier`), the stub symbols are already strong definitions, so just use `__attribute__((weak))` in your patch source.

## Linker errors
In the case of linker errors, helpful troubleshooting approaches are:

- find the linker command line in the OFRAK log, then:
    - inspect the generated linker script (`-T/path/to/linker_script.ld` in the command line). Check if the addresses, sizes, alignments match the expected values.
    - inspect the map file (`-Map /path/to/map_file.map` in the command line). Check if things land where they're expected to, compared to the linker script.
    - inspect the linker options to check if they are the expected ones

If anything strange stands up during the above inspection, use the toolchains directly to diagnose
what the PatchMaker needs (fixups in the linker script generation, change in the command line
arguments, etc.), and then fix it in the PatchMaker setup/usage.

## General troubleshooting tips:
- the standalone assembler/compiler/linker commands can be run on the command line manually while experimenting, avoiding running the full OFRAK script
- different toolchains will handle compilation differently, and unless prohibited by the use case, it may be helpful to change the employed toolchain to further triage the error (or even get past it)
