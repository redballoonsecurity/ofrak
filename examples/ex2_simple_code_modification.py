"""
This example showcases the simplicity of performing binary code modifications with OFRAK.

The input program is a compiled binary ELF file which prints "Hello, World!" to the console.

```c
#include <stdio.h>
int main() {
   printf("Hello, World!\n");
   return 0;
}
```

The example performs code modification in the input binary (without extension). It leverages
BinaryNinja to analyze the executable binary, and Keystone to rewrite an instruction so that the
binary loops back to its beginning instead of returning and exiting at the end of the main function.

Someone is chasing its tail and never catching it 😹
"""
import argparse
import os

import ofrak_binary_ninja
import ofrak_capstone
from ofrak import OFRAK, OFRAKContext, ResourceFilter, ResourceAttributeValueFilter
from ofrak.core import (
    ProgramAttributes,
    BinaryPatchConfig,
    BinaryPatchModifier,
    ComplexBlock,
    Instruction,
)
from ofrak.service.assembler.assembler_service_keystone import KeystoneAssemblerService

ASSETS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "assets"))
BINARY_FILE = os.path.join(ASSETS_DIR, "example_program")


async def main(ofrak_context: OFRAKContext, file_path: str, output_file_name: str):
    # Create resource
    binary_resource = await ofrak_context.create_root_resource_from_file(file_path)

    # Unpack resource
    await binary_resource.unpack_recursively()
    # Get the "main" function complex block
    main_cb = await binary_resource.get_only_descendant_as_view(
        v_type=ComplexBlock,
        r_filter=ResourceFilter(
            attribute_filters=(ResourceAttributeValueFilter(ComplexBlock.Symbol, "main"),)
        ),
    )
    # Get the ret instruction within the main function
    ret_instruction = await main_cb.resource.get_only_descendant_as_view(
        v_type=Instruction,
        r_filter=ResourceFilter(
            attribute_filters=(ResourceAttributeValueFilter(Instruction.Mnemonic, "ret"),)
        ),
    )

    # Assemble the code modification using Keystone assembler
    # Modification: jump to the main function's entry point, creating an infinite loop
    assembler_service = KeystoneAssemblerService()
    program_attributes = await binary_resource.analyze(ProgramAttributes)
    new_instruction_bytes = await assembler_service.assemble(
        assembly=f"jmp {main_cb.virtual_address}",
        vm_addr=ret_instruction.virtual_address,
        program_attributes=program_attributes,
    )

    # Patch in the modified bytes
    range_in_root = await ret_instruction.resource.get_data_range_within_root()
    binary_injector_config = BinaryPatchConfig(
        range_in_root.start,
        new_instruction_bytes,
    )
    await binary_resource.run(BinaryPatchModifier, binary_injector_config)

    # Dump the modified program to disk
    await binary_resource.pack()
    await binary_resource.flush_to_disk(output_file_name)
    print(f"Done! Output file written to {output_file_name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--hello-world-file", default=BINARY_FILE)
    parser.add_argument("--output-file-name", default="./example_2_infinite_hello")
    args = parser.parse_args()

    ofrak = OFRAK()
    ofrak.injector.discover(ofrak_capstone)
    ofrak.injector.discover(ofrak_binary_ninja)
    ofrak.run(main, args.hello_world_file, args.output_file_name)
