# OFRAK PatchMaker

## What is OFRAK PatchMaker?
PatchMaker is a Python package for building code patch blobs from source and injecting them into an executable OFRAK
resource. Once a patch is applied to a Resource, it may be re-packed with OFRAK the same way as if only a string
modification were applied.

PatchMaker takes additional steps beyond the typical C software build process to ensure that new code and data, provided
in C/asm source or binary form, land where they are supposed to and that linking against existing code and data in the
target binary is easy.

Think of it as a way to compile custom code using the binary-under-analysis as a library. Normally a loader is
responsible for mapping external symbols correctly into the loaded executable's memory space. With PatchMaker the
process is inverted: once the patch is compiled, it can be injected into the host binary with the patch's external
symbols correctly linked to the host's internal symbols, without involving a loader.

## How does PatchMaker work?
PatchMaker implements an interface to _toolchain backends_: currently GCC, LLVM and VBCC. The toolchain backend
implementations can be found in `ofrak_patch_maker.toolchain`
which mostly consist of linker script constructors and compiler flag mappings (to general options defined in
[ToolchainConfig][ofrak_patch_maker.toolchain.model.ToolchainConfig]).

The user writes source code for modifications to be made against a target binary. That source may reference symbols baked
into the target binary, so the user also declares external symbols in the source and their respective addresses in
PatchMaker. Source targets, external symbols used by the patch, and toolchain configuration are passed to the selected
toolchain backend. The backend translates these definitions into toolchain-specific command-line arguments and linker
scripts, then runs the toolchain compiler on the generated results.

```
                        __________
                       |  Header  |  ------- ,
                       |__________|           \                        ,-> [ Object output ]
 ______________         _________________      \        ______________/__         _______________
|  PatchMaker  |  ==>  |  Linker Script  |  --- * ==>  |  GCC/LLVM/VBCC  |  ==>  |  ELF/PE/etc.  | 
|______________|       |_________________|     /       |_________________|       |_____(FEM)_____|
                        ______________        /
                       |  Linker map  |  --- `
                       |______________|
```

After running PatchMaker in tutorial
[lesson 6](https://github.com/redballoonsecurity/ofrak/blob/master/ofrak_tutorial/notebooks_with_outputs/6_code_insertion_with_extension.ipynb), the build directory provided
to it should look something like this (the tmp sub-directory will vary and be defined in the `bld_dir` variable, if you
want to try yourself):

```
root@ofrak:/tmp/tmp08588tpq# tree
.
|-- base_symbols_vd66jeq0.inc      # Header
|-- hello_world_patch_bom_files
|   `-- c_patch.c.o                # Object output
|-- hello_world_patch_exec         # FEM
|-- hello_world_patch_exec.map     # Linker map
`-- hello_world_patch_u32yyd5z.ld  # Linker script
```

the `.inc`, `.map` and `.ld` files are the generated header, linker map and linker script files accordingly. They
specify the symbols, their locations, and the locations of segments. Here is the build directory after running
[lesson 6](https://github.com/redballoonsecurity/ofrak/blob/master/ofrak_tutorial/notebooks_with_outputs/6_code_insertion_with_extension.ipynb) when we wrap a call to `puts`:

##### Header:
```
PROVIDE(puts = 0x401030);
```

##### Linker map:
```
    VMA              LMA     Size Align Out     In      Symbol
      0                0        0     1 PROVIDE ( puts = 0x401030 )
 405000           405000       45     4 .rbs_c_patch_text
 405000           405000       45     4         /tmp/tmp08588tpq/hello_world_patch_bom_files/c_patch.c.o:(.text)
 405000           405000       45     1                 uppercase_and_print
      0                0       60     8 .symtab
      0                0       60     8         <internal>:(.symtab)
      0                0       2d     1 .shstrtab
      0                0       2d     1         <internal>:(.shstrtab)
      0                0       24     1 .strtab
      0                0       24     1         <internal>:(.strtab)
```

##### Linker script:
```
INCLUDE /tmp/tmp08588tpq/base_symbols_vd66jeq0.inc

MEMORY
{
    ".rbs_c_patch_text_mem" (rx) : ORIGIN = 0x405000, LENGTH = 0x2000
}

SECTIONS
{
    .rbs_c_patch_text : {
        /tmp/tmp08588tpq/hello_world_patch_bom_files/c_patch.c.o(.text)
    } > ".rbs_c_patch_text_mem"

    /DISCARD/ : {
        *(.gnu.hash)
        *(.comment)
        *(.ARM.attributes)
        *(.dynamic)
        *(.ARM.exidx)
        *(.hash)
        *(.dynsym)
        *(.dynstr)
        *(.eh_frame)
    }
}
```

The main output `hello_world_patch_exec` is a minimal ELF executable which only contains the segment with the compiled
patch code, a section entry for it, and a minimal set of symbols and nothing else.

```
root@ofrak:/tmp/tmp08588tpq# readelf -ls hello_world_patch_exec

Elf file type is EXEC (Executable file)
Entry point 0x0
There are 2 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000001000 0x0000000000405000 0x0000000000405000
                 0x0000000000000045 0x0000000000000045  R E    0x1000
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x0

 Section to Segment mapping:
  Segment Sections...
   00     .rbs_c_patch_text 
   01     

Symbol table '.symtab' contains 4 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS c_patch.c
     2: 0000000000401030     0 NOTYPE  GLOBAL DEFAULT  ABS puts
     3: 0000000000405000    69 FUNC    GLOBAL DEFAULT    1 uppercase_and_print

```

This ELF is called the Final Executable and Metadata (FEM) and is essentially scaffolding to hold code for functions
yet-to-be injected into the binary-under-analysis, as well as the symbols necessary to correctly re-link to it.

## Suggested Workflow

### Using PatchMaker with OFRAK resources

PatchMaker is made to work with OFRAK resources, but does not require them. By itself, PatchMaker compiles a minimal
binary (ELF, PE or otherwise) containing the segment with the compiled patches and symbols mapped to the
binary-under-analysis. PatchMaker can be further tweaked to include `.bss` and debug sections, which are
described in the [ToolchainConfig][ofrak_patch_maker.toolchain.model.ToolchainConfig].

The symbol location map is described through `base_symbols`, when `PatchMaker` is instantiated. These locations can be
derived from an OFRAK resource, but they don't have to be since they are simply memory addresses. In 
[lesson 6](https://github.com/redballoonsecurity/ofrak/blob/master/ofrak_tutorial/notebooks_with_outputs/6_code_insertion_with_extension.ipynb) we provide an example for using
OFRAK to do this anyway, and tell PatchMaker the symbol-address mapping that corresponds to `puts` in the
binary-under-analysis; you could see that we could have gotten this number directly from readelf, or even made one up:

```
# Get the complex block containing the code for `puts`
puts_complex_block = await root_resource.get_only_descendant_as_view(
    v_type   = ComplexBlock,
    r_filter = ResourceFilter(
        attribute_filters = (ResourceAttributeValueFilter(ComplexBlock.Symbol, "puts"),)
    ),
)

base_symbols = { "puts" : puts_cb.virtual_address, }
```

The part where OFRAK comes in with PatchMaker is in its ability to extend executables to make room for patch blobs, to
make specific instruction-level patches [(see lesson 4)](https://github.com/redballoonsecurity/ofrak/tree/master/ofrak_tutorial/notebooks_with_outputs/4_simple_code_modification.ipynb),
and to take PatchMaker's results to re-import the compiled patch into the binary-under-analysis... all while keeping the
same programming interface to tweak and define all of these steps in a scriptable manner.

In this suggested workflow we closely use the workflow used for
[lesson 6](https://github.com/redballoonsecurity/ofrak/tree/master/ofrak_tutorial/notebooks_with_outputs/6_code_insertion_with_extension.ipynb), which demonstrates extending an
ELF with OFRAK's interface to [LIEF](https://github.com/lief-project/LIEF) and injecting the PatchMaker compiled patches
into the resource using OFRAK core `BinaryPatchConfig` before and after using PatchMaker.

---

### Pre-PatchMaker steps (using OFRAK)
#### [1] Unpack the binary-under-analysis onto an OFRAK resource tree:
```
resource = await binary_analysis_context.create_root_resource_from_file(binary)
```

#### [2] Extend the binary-under-analysis with a new segment, if we wish to inject the patch there:
```
config = LiefAddSegmentConfig(vaddr, PAGE_ALIGN, [0 for _ in range(size)], "rx")
await resource.run(LiefAddSegmentModifier, config)
```

We can then retrieve the OFRAK resource representing the new segment, derive its entry-point address and patch branches
/ calls in the binary-under-analysis to use that destination instead.

#### [3] Patch any instruction-level control flow to make the patch work / get called, if required:
```
call_instruction = await main_cb.resource.get_only_descendant_as_view(
        v_type=Instruction,
        r_filter=ResourceFilter(
            attribute_filters=(ResourceAttributeValueFilter(Instruction.Mnemonic, "call"),)
        ),
    )
await call_instruction.modify_assembly("call", f"0x{new_segment.p_vaddr:x}")
```

The steps [2] and [3] may be done in the post-PatchMaker stage, especially if certain information can only be known
after the PatchMaker steps (for instance, if entrypoint addresses of the functions themselves are required for the
instruction-level patches).

---

### PatchMaker steps
Compile the patch source using OFRAK PatchMaker, after defining the arch info, toolchain and symbols we wish to
re-link to the target-under-analysis.

This is composed of a few steps in itself, which are:

- Define the `ArchInfo` dataclass, which specifies the target CPU, ISA, etc.;
- Define the `ToolchainConfig` dataclass, which specifies toolchain configuration parameters, such as optimization flags, reloc flags, etc.;
- Initialize a `Toolchain` with the arch info and toolchain config;
- Initialize `PatchMaker` with the toolchain and the symbol addresses to re-link, which in;
- Define the `BOM` (Batch of Objects and Metadata) dataclass to include the source file with the `uppercase_and_print` patch;
- Define the `PatchRegionConfig` dataclass describing the object files of the patch; then finally,
- Compile the patch into a `FEM` (Final Executable and Metadata) object.

First, certain information needs to be known ahead of time:

#### ArchInfo
Specify the CPU / ISA related parameters of the binary-under-analysis:
```
dataclass ArchInfo:
  isa:        InstructionSet
  sub_isa:    Optional[SubInstructionSet]
  bit_width:  BitWidth
  endianness: Endianness
  processor:  Optional[ProcessorType]
```

#### Toolchain configuration
Specify compiler flags, optimization levels, spare-area tunables, etc.

There are many parameters accepted by `ToolchainConfig`, but some important ones are:
```
dataclass ToolchainConfig:
  file_format:     BinFileType
  force_inlines:   bool
  relocatable:     bool
  no_std_lib:      bool
  no_jump_tables:  bool
  no_bss_section:  bool
  compiler_optimization_level: CompilerOptimizationLevel  
```
Check out the [ToolchainConfig][ofrak_patch_maker.toolchain.model.ToolchainConfig] for the full suite
of tunables (they are likely to get updated frequently while OFRAK is developed).

Together, [ArchInfo][ofrak_type.architecture.ArchInfo] and [ToolchainConfig][ofrak_patch_maker.toolchain.model.ToolchainConfig] can be used to instantiate a [Toolchain][ofrak_patch_maker.toolchain.abstract.Toolchain].


#### PatchMaker Instantiation
Once the toolchain is instantiated, instantiate PatchMaker with any symbol mapping that may be required to link the patch. Note that this may not be required if the developer's patch does not reference external functions or data.

We can get the virtual address of the functions that the patch will need to import, for instance:

```
# Get the complex block containing the code for `puts`
puts_complex_block = await root_resource.get_only_descendant_as_view(
    v_type   = ComplexBlock,
    r_filter = ResourceFilter(
        attribute_filters = (ResourceAttributeValueFilter(ComplexBlock.Symbol, "puts"),)
    ),
)

base_symbols = { "puts" : puts_cb.virtual_address, }
```

Then we instantiate PatchMaker with that mapping:

```
class PatchMaker:
    toolchain:  Toolchain,
    platform_includes:   Optional[Iterable[str]] = None,
    base_symbols:        Mapping[str, int]       = None,
    build_dir:           str                     = ".",
    logger:              logging.Logger          = logging.getLogger()
```

#### BOM (Batched Objects and Metadata)
With PatchMaker instantiated, build the BOM specifying the source, object and header files to be included in the build.
This allows us to be modular with our patch source code, and include objects that already have been compiled elsewhere.

We can use PatchMaker to generate a BOM with `make_bom`, knowing only the build target inputs for our patch:
```
function PatchMaker.make_bom
        name:              str,
        source_list:       List[str],
        object_list:       List[str],
        header_dirs:       List[str],
        entry_point_name:  Optional[str] = None,
```

`make_bom` collects the inputs, assembles them with the toolchain, and returns a BOM for PatchMaker:

```
dataclass BOM:
    name:                str
    object_map:          Mapping[str, AssembledObject]
    bss_size_required:   int
    entry_point_symbol:  Optional[str]
```

#### Patch Region Configuration
Using the generated BOM, create a Patch Region Configuration specifying the segment in which we want to store the
compiled patch code (from within the FEM itself!):

```
# The FEM segment to contain the patch
text_segment_uppercase = Segment(
    segment_name=".text",
    vm_address=new_segment.p_vaddr,
    offset=0,
    is_entry=False,
    length=new_segment.p_filesz,
    access_perms=MemoryPermissions.RX,
)

# The source input for the c patch ...
uppercase_object = bom.object_map[c_patch_filename]

# ... is to be mapped into the segment we have just created
segment_dict = {
    uppercase_object.path: (text_segment_uppercase,),
}

# Now to put it together
patch_region_config = PatchRegionConfig(bom.name + "_patch", segment_dict)
```

#### FEM (Final Executable and Metadata)
All the setup is done, we can finally use PatchMaker to generate a minimal ELF:

```
fem = patch_maker.make_fem([(bom, p)], exec_path)
```
You should find your FEM in `exec_path`. Open it with Ghidra and take a look!

---
### Post-PatchMaker steps (using OFRAK)
The FEM can be used directly with OFRAK, and incorporating the patch takes two more steps: **Injection** and **Packing**.

These steps are done through OFRAK core, and are described individually in the OFRAK tutorial as well as in
[lesson 6](https://github.com/redballoonsecurity/ofrak/tree/master/ofrak_tutorial/notebooks_with_outputs/6_code_insertion_with_extension.ipynb).

#### Injection
Inject the extended ELF segment with the compiled patch blob using OFRAK `SegmentInjectorModifier`.

```
await root_resource.run(SegmentInjectorModifier, config=SegmentInjectorModifierConfig.from_fem(fem))
```

#### Packing
Finally, the familiar step of packing the results
```
await root_resource.pack()
await root_resource.flush_data_to_disk(output_filename)
```

### Troubleshooting

This package attempts to be rigid in the hopes that, by the time it allows the generation of a FEM object, the developer
can be confident that the code and data will be placed correctly, and any references to existing code and data in the target
binary are linked correctly. PatchMaker raises liberally when encountering an unexpected use case.

Of course, just as when driving a compiler directly, there is no escaping compiler, linker, or assembler errors. While
developing new C/asm patches, developers should expect to reference the build_dir provided to the PatchMaker instance
for artifacts that will guide in the debug.

These include:

- Compiled object files
- Generated symbol files (for GNU syntax, the .inc file extension)
- Generated linker scripts (for GNU syntax, the .ld file extension)
- Linker-generated map files, that include section placement in memory during/after link
- The resulting executable wrapped in the FEM, should link succeed

For more information please refer to the [PatchMaker troubleshooting guide](troubleshooting.md).

<div align="right">
<img src="../../../assets/square_03.png" width="125" height="125">
</div>
