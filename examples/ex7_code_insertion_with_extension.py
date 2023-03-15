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
import os

from ofrak_patch_maker.toolchain.llvm_12 import LLVM_12_0_1_Toolchain

import ofrak_ghidra
from ofrak import OFRAK, OFRAKContext, Resource, ResourceFilter, ResourceAttributeValueFilter
from ofrak.core import (
    Allocatable,
    CodeRegion,
    ComplexBlock,
    Instruction,
    LiefAddSegmentConfig,
    LiefAddSegmentModifier,
    ElfProgramHeader,
)
from ofrak.core.patch_maker.modifiers import (
    PatchFromSourceModifier,
    PatchFromSourceModifierConfig,
    SourceBundle,
)
from ofrak_patch_maker.toolchain.model import (
    ToolchainConfig,
    BinFileType,
    CompilerOptimizationLevel,
    Segment,
)
from ofrak_patch_maker.toolchain.utils import get_file_format
from ofrak_type import Range
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
    segment = [seg for seg in file_segments if seg.p_vaddr == vaddr].pop()

    # Carve out a child of the new segment where we can store the code for our new function.
    code_region = CodeRegion(segment.p_vaddr + GHIDRA_PIE_OFFSET, segment.p_filesz)
    code_region.resource = await elf_resource.create_child_from_view(
        code_region, data_range=Range(segment.p_offset, segment.p_offset + segment.p_filesz)
    )
    elf_resource.add_tag(Allocatable)
    await elf_resource.save()

    return segment


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
    # The PatchMaker will need to know how to configure the build toolchain.
    tc_config = ToolchainConfig(
        file_format=BinFileType.ELF,
        force_inlines=True,
        relocatable=True,
        no_std_lib=True,
        no_jump_tables=True,
        no_bss_section=True,
        create_map_files=True,
        compiler_optimization_level=CompilerOptimizationLevel.SPACE,
        debug_info=False,
        check_overlap=False,
    )

    # Tell the PatchMaker about the segment we added in the binary...
    text_segment_uppercase = Segment(
        segment_name=".text",
        vm_address=new_segment.p_vaddr + GHIDRA_PIE_OFFSET,
        offset=0,
        is_entry=False,
        length=new_segment.p_filesz,
        access_perms=MemoryPermissions.RX,
    )

    # ... And that we want to put the compiled C patch there.
    uppercase_source: str = os.path.join(source_dir, "uppercase.c")
    segment_dict = {
        uppercase_source: (text_segment_uppercase,),
    }

    # Tell PatcherFromSourceModifier about the source files, toolchain, and patch name.
    patch_from_source_config = PatchFromSourceModifierConfig(
        SourceBundle.slurp(source_dir),
        segment_dict,
        tc_config,
        LLVM_12_0_1_Toolchain,
        patch_name="HELLO_WORLD",
    )

    # Run PatchFromSourceModifier, which will analyze the target binary, run PatchMaker on our
    # patch, create a Batch of Objects and Metadata (BOM) for the patch, create a BOM from the
    # target binary for all unresolved symbols in the patch, make a Final Executable and Metadata
    # (FEM), and then inject our patch into the binary.
    await resource.run(PatchFromSourceModifier, patch_from_source_config)


async def main(ofrak_context: OFRAKContext, file_path: str, output_file_name: str):
    try:
        root_resource = await ofrak_context.create_root_resource_from_file(file_path)
    except FileNotFoundError:
        raise RuntimeError(
            f"Cannot find the file {file_path}. Did you run the Makefile to build it?"
        )

    new_segment = await add_and_return_segment(root_resource, 0x108000, 0x2000)
    source_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "src", "example_7"))
    await patch_uppercase(root_resource, source_dir, new_segment)
    await call_new_segment_instead(root_resource, new_segment)

    await root_resource.pack()
    await root_resource.flush_to_disk(output_file_name)

    assert os.path.exists(output_file_name)
    assert get_file_format(output_file_name) == BinFileType.ELF

    print(f"Done! Output file written to {output_file_name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--hello-world-file", default=BINARY_FILE)
    parser.add_argument("--output-file-name", default="./example_7_uppercase")
    args = parser.parse_args()

    ofrak = OFRAK()
    ofrak.discover(ofrak_ghidra)
    ofrak.run(main, args.hello_world_file, args.output_file_name)
