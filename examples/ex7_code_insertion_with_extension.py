"""
This example showcases the code insertion and extension capabilities of OFRAK.

The input program is a compiled binary ELF file which prints "Hello, World!" to the console.

```c
#include <stdio.h>
int main() {
   printf("Hello, World!\n");
   return 0;
}
```

The example adds a new segment in the ELF, and patches in the following code that turns all
lowercase characters to uppercase. Patching the code leverages the OFRAK PatchMaker, including
linking to the pre-existing `puts` function in the input ELF binary.

```c
extern int _puts(char *str);

void uppercase_and_print(char *text)
{
    char str[15] = {0};
    for(int i=0; i<14; i++){
        // if character is a lowercase letter make it uppercase:
        if(text[i] >= 0x61 && text[i] <= 0x7A)
            str[i] = text[i]-0x20;
        else
            str[i] = text[i];
    }
    _puts(str);
}
```

KITTEH! 🙀
"""
import argparse
import logging
import os
import tempfile

import ofrak_ghidra
from ofrak import OFRAK, OFRAKContext, Resource, ResourceFilter, ResourceAttributeValueFilter
from ofrak.core import (
    ProgramAttributes,
    InstructionSet,
    BinaryPatchConfig,
    BinaryPatchModifier,
    ComplexBlock,
    Instruction,
    LiefAddSegmentConfig,
    LiefAddSegmentModifier,
    ElfProgramHeader,
)
from ofrak_patch_maker.model import PatchRegionConfig
from ofrak_patch_maker.patch_maker import PatchMaker
from ofrak_patch_maker.toolchain.model import (
    ToolchainConfig,
    BinFileType,
    CompilerOptimizationLevel,
    Segment,
)
from ofrak_patch_maker.toolchain.utils import get_file_format
from ofrak_patch_maker.toolchain.version import ToolchainVersion
from ofrak_type.bit_width import BitWidth
from ofrak_type.endianness import Endianness
from ofrak_type.memory_permissions import MemoryPermissions

ASSETS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "assets"))
BINARY_FILE = os.path.join(ASSETS_DIR, "example_program")
PAGE_ALIGN = 0x1000
GHIDRA_PIE_OFFSET = 0x100000  # Ghidra bases PIE executables at 0x100000


async def add_and_return_segment(elf_resource: Resource, vaddr: int, size: int) -> ElfProgramHeader:
    """Add a segment to `elf_resource`, of size `size` at virtual address `vaddr`,
    returning this new segment resource after unpacking."""

    config = LiefAddSegmentConfig(vaddr, PAGE_ALIGN, [0 for _ in range(size)], "rx")
    await elf_resource.run(LiefAddSegmentModifier, config)
    await elf_resource.unpack_recursively()

    # Get our newly added segment. First get all ElfProgramHeaders, then return the one
    # with our virtual address.
    file_segments = await elf_resource.get_descendants_as_view(
        ElfProgramHeader, r_filter=ResourceFilter(tags=(ElfProgramHeader,))
    )
    return [seg for seg in file_segments if seg.p_vaddr == vaddr].pop()


async def call_new_segment_instead(resource: Resource, new_segment: ElfProgramHeader):
    """Replace the original `call` instruction in main with a call to the start of `new_segment`."""
    main_cb = await resource.get_only_descendant_as_view(
        v_type=ComplexBlock,
        r_filter=ResourceFilter(
            attribute_filters=(ResourceAttributeValueFilter(ComplexBlock.Symbol, "main"),)
        ),
    )
    call_instruction = await main_cb.resource.get_only_descendant_as_view(
        v_type=Instruction,
        r_filter=ResourceFilter(
            attribute_filters=(ResourceAttributeValueFilter(Instruction.Mnemonic, "call"),)
        ),
    )

    ghidra_new_segment_vaddr = new_segment.p_vaddr + GHIDRA_PIE_OFFSET
    await call_instruction.modify_assembly("call", f"0x{ghidra_new_segment_vaddr:x}")


async def patch_uppercase(resource: Resource, source_dir: str, new_segment: ElfProgramHeader):
    # The PatchMaker will need to know a bit about the target architecture
    # since it will compile our C patch.
    proc = ProgramAttributes(
        isa=InstructionSet.X86,
        sub_isa=None,
        bit_width=BitWidth.BIT_64,
        endianness=Endianness.BIG_ENDIAN,
        processor=None,
    )

    # ... And also more details about how to configure the build toolchain.
    tc_config = ToolchainConfig(
        file_format=BinFileType.ELF,
        force_inlines=True,
        relocatable=False,
        no_std_lib=True,
        no_jump_tables=True,
        no_bss_section=True,
        create_map_files=True,
        compiler_optimization_level=CompilerOptimizationLevel.SPACE,
        debug_info=False,
        check_overlap=False,
    )

    # Get the complex block containing the code for `puts`
    puts_cb = await resource.get_only_descendant_as_view(
        v_type=ComplexBlock,
        r_filter=ResourceFilter(
            attribute_filters=(ResourceAttributeValueFilter(ComplexBlock.Symbol, "puts"),)
        ),
    )
    # Initialize the PatchMaker. This is where we tell it that our `_puts` will
    # need to be linked to the address of the existing `puts`.
    logger = logging.getLogger("ToolchainTest")
    logger.setLevel("INFO")
    build_dir = tempfile.mkdtemp()
    patch_maker = PatchMaker(
        program_attributes=proc,
        toolchain_config=tc_config,
        toolchain_version=ToolchainVersion.LLVM_12_0_1,
        logger=logger,
        build_dir=build_dir,
        base_symbols={"_puts": puts_cb.virtual_address - GHIDRA_PIE_OFFSET},
    )

    # Make a Batch of Objects and Metadata (BOM)
    # This basically corresponds to the step of building the object files, before linking,
    # but this gives us more fine-grained control if we wish to.
    uppercase_source: str = os.path.join(source_dir, "uppercase.c")
    source_list = [uppercase_source]
    bom = patch_maker.make_bom(
        name="hello_world_patch",
        source_list=source_list,
        object_list=[],
        header_dirs=[],
    )

    # Get the resulting object paths and re-map them to the segments we chose for each source file.
    uppercase_object = bom.object_map[uppercase_source]

    # Tell the PatchMaker about the segment we added in the binary...
    text_segment_uppercase = Segment(
        segment_name=".text",
        vm_address=new_segment.p_vaddr,
        offset=0,
        is_entry=False,
        length=new_segment.p_filesz,
        access_perms=MemoryPermissions.RX,
    )
    # ... And that we want to put the compiled C patch there.
    segment_dict = {
        uppercase_object.path: (text_segment_uppercase,),
    }

    # Generate a PatchRegionConfig incorporating the previous information
    p = PatchRegionConfig(bom.name + "_patch", segment_dict)

    # Tell the PatchMaker where to write the final executable
    exec_path = os.path.join(build_dir, "hello_world_path_exec")

    # Make the Final Executable and Metadata (FEM)
    fem = patch_maker.make_fem([(bom, p)], exec_path)

    assert os.path.exists(exec_path)
    assert get_file_format(exec_path) == tc_config.file_format

    # At this point, the PatchMaker has produced an executable containing our new segment.
    # Let's read it, find the binary data of the segment, and finally patch that binary
    # data into our resource.
    with open(fem.executable.path, "rb") as f:
        exe_data = f.read()

    # Retrieve the binary data of our new segment
    segment_data = b""
    for segment in fem.executable.segments:
        if segment.length == 0 or segment.vm_address == 0:
            continue
        if segment.length > 0:
            logger.info(
                f"    Segment {segment.segment_name} - {segment.length} "
                f"bytes @ {hex(segment.vm_address)}"
            )
        segment_data = exe_data[segment.offset : segment.offset + segment.length]
        break
    assert len(segment_data) != 0

    # Patch the compiled code in the new_segment
    patch_config = BinaryPatchConfig(new_segment.p_offset, segment_data)
    await resource.run(BinaryPatchModifier, patch_config)


async def main(ofrak_context: OFRAKContext, file_path: str, output_file_name: str):
    try:
        root_resource = await ofrak_context.create_root_resource_from_file(file_path)
    except FileNotFoundError:
        raise RuntimeError(
            f"Cannot find the file {file_path}. Did you run the Makefile to build it?"
        )

    new_segment = await add_and_return_segment(root_resource, 0x108000, 0x2000)
    source_dir = os.path.join(os.path.dirname(__file__), "src/example_7")
    await patch_uppercase(root_resource, source_dir, new_segment)
    await call_new_segment_instead(root_resource, new_segment)

    await root_resource.pack()
    await root_resource.flush_to_disk(output_file_name)
    print(f"Done! Output file written to {output_file_name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--hello-world-file", default=BINARY_FILE)
    parser.add_argument("--output-file-name", default="./example_7_uppercase")
    args = parser.parse_args()

    ofrak = OFRAK()
    ofrak.discover(ofrak_ghidra)
    ofrak.run(main, args.hello_world_file, args.output_file_name)
