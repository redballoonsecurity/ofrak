"""
This example showcases the `PatchMaker` code modification capabilities of OFRAK.

The input program is a compiled binary ELF file which prints "Hello, World!" to the console, but
also includes a `print_kitteh` function, not invoked by `main`.

```c
#include <stdio.h>

// Force no inline to demonstrate how main can be patched to call a different function
int __attribute__((noinline)) print_hello_world() {
    printf("Hello, World!\n");
    return 0;
}

int print_kitteh() {
    printf("kitteh! demands obedience...\n");
    return 0;
}

int main() {
   print_hello_world();
   return 0;
}
```

The example compiles and links in the following code leveraging the `PatchMaker`. The resulting code
replaces the `main` function so that instead of calling the `print_hello_world` function, `main`
calls the `print_kitteh` function, for increased demands of obedience 😸

```c
int main() {
   print_kitteh();
   return 0;
}
```
"""
import argparse
import logging
import os
import tempfile

from ofrak_patch_maker.toolchain.llvm_12 import LLVM_12_0_1_Toolchain

import ofrak_ghidra
from ofrak import OFRAK, OFRAKContext, ResourceFilter, ResourceAttributeValueFilter
from ofrak.core import (
    ProgramAttributes,
    ComplexBlock,
    SegmentInjectorModifierConfig,
    SegmentInjectorModifier,
)
from ofrak_patch_maker.model import PatchRegionConfig
from ofrak_patch_maker.patch_maker import PatchMaker
from ofrak_patch_maker.toolchain.model import (
    BinFileType,
    ToolchainConfig,
    CompilerOptimizationLevel,
    Segment,
)
from ofrak_type.memory_permissions import MemoryPermissions

PAGE_ALIGN = 0x1000
BINARY_FILE = "./src/example_6/program_kitteh"
PRINT_KITTEH_SOURCE = "./src/example_6/print_kitteh.c"


async def main(
    ofrak_context: OFRAKContext, file_path: str, print_kitteh_source: str, output_file_name: str
):
    try:
        root_resource = await ofrak_context.create_root_resource_from_file(file_path)
    except FileNotFoundError:
        raise RuntimeError(
            f"Cannot find the file {file_path}. Did you run the Makefile to build it?"
        )

    await root_resource.unpack_recursively(do_not_unpack=(ComplexBlock,))

    # The PatchMaker will need to know a bit about the target architecture
    # since it will compile our C patch.
    program_attributes = await root_resource.analyze(ProgramAttributes)

    # ... And also more details about how to configure the build toolchain.
    tc_config = ToolchainConfig(
        file_format=BinFileType.ELF,
        force_inlines=True,
        relocatable=True,
        no_std_lib=True,
        no_jump_tables=True,
        no_bss_section=True,
        create_map_files=True,
        compiler_optimization_level=CompilerOptimizationLevel.FULL,
        debug_info=True,
    )

    # Get the complex block for `main`
    main_cb = await root_resource.get_only_descendant_as_view(
        v_type=ComplexBlock,
        r_filter=ResourceFilter(
            attribute_filters=(ResourceAttributeValueFilter(ComplexBlock.Symbol, "main"),)
        ),
    )
    print(main_cb)

    # Get the complex block for `print_kitteh`
    print_kitteh_function = await root_resource.get_only_descendant_as_view(
        v_type=ComplexBlock,
        r_filter=ResourceFilter(
            attribute_filters=(ResourceAttributeValueFilter(ComplexBlock.Symbol, "print_kitteh"),)
        ),
    )
    print(print_kitteh_function)

    # Initialize the PatchMaker. This is where we tell it that the `print_kitteh` in our patch will
    # need to be linked to the address of the existing `print_kitteh`.
    logger = logging.getLogger("ToolchainTest")
    logger.setLevel("INFO")
    build_dir = tempfile.mkdtemp()
    toolchain = LLVM_12_0_1_Toolchain(program_attributes, tc_config)
    patch_maker = PatchMaker(
        toolchain=toolchain,
        logger=logger,
        build_dir=build_dir,
        base_symbols={
            "print_kitteh": print_kitteh_function.virtual_address,
        },
    )

    # Tell the PatchMaker where our patch should go: it should overwrite `main`.
    text_segment = Segment(
        segment_name=".text",
        vm_address=main_cb.virtual_address,
        offset=0,
        is_entry=False,
        length=main_cb.size,
        access_perms=MemoryPermissions.RX,
    )
    manual_map = {
        print_kitteh_source: (text_segment,),
    }

    # Make a Batch of Objects and Metadata (BOM)
    # This basically corresponds to the step of building the object files, before linking,
    # but this gives us more fine-grained control if we wish to.
    bom = patch_maker.make_bom(
        name="kitteh",
        source_list=[print_kitteh_source],
        object_list=[],
        header_dirs=[],
    )

    # Grab the resulting object paths and re-map them to the segments we chose for each source file.
    segment_dict = {}
    for src_file in manual_map.keys():
        object_path = bom.object_map[src_file].path
        segment_dict[object_path] = manual_map[src_file]

    # Generate a PatchRegionConfig incorporating the previous information
    p = PatchRegionConfig(bom.name + "_patch", segment_dict)

    # Tell the PatchMaker where to write the final executable
    exec_path = os.path.join(build_dir, "fem")

    # Make the Final Executable and Metadata (FEM)
    fem = patch_maker.make_fem([(bom, p)], exec_path)

    # Inject the patch
    await root_resource.run(SegmentInjectorModifier, SegmentInjectorModifierConfig.from_fem(fem))

    await root_resource.pack()
    await root_resource.flush_data_to_disk(output_file_name)
    print(f"Done! Output file written to {output_file_name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--hello-world-file", default=BINARY_FILE)
    parser.add_argument("--print-kitteh-source", default=PRINT_KITTEH_SOURCE)
    parser.add_argument("--output-file-name", default="./example_6_kitteh")
    args = parser.parse_args()

    ofrak = OFRAK()
    ofrak.discover(ofrak_ghidra)
    ofrak.run(main, args.hello_world_file, args.print_kitteh_source, args.output_file_name)
