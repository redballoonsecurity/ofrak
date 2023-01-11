"""
This example showcases the binary extension capabilities of OFRAK.

The input program is a compiled binary ELF file which prints "Hello, World!" to the console.

```c
#include <stdio.h>
int main() {
   printf("Hello, World!\n");
   return 0;
}
```

The example adds a new segment in the input ELF binary, and rewrites the binary to print the
following ASCII art instead of boring "Hello, World!".

```text
       | | | |  ___  | || |  ___   | | / /(_)  _     _
       | |_| | / _ \\ | || | / _ \\  | |/ /  _ _| |_ _| |_  _  _
       |  _  |/ /_\\ \\| || |/ / \\ \\ |   /  | |_   _|_   _|| |/ /
       | | | |\\ ,___/| || |\\ \\_/ / | |\\ \\ | | | |_  | |_ | / /
       |_| |_| \\___/ |_||_| \\___/  |_| \\_\\|_| \\___| \\___||  /
                              _           _              / /
                             / \\_______ /|_\\             \\/
                            /          /_/ \\__
                           /             \\_/ /
                         _|_              |/|_
                         _|_  O    _    O  _|_
                         _|_      (_)      _|_
                          \\                 /
                           _\\_____________/_
                          /  \\/  (___)  \\/  \
                          \\__(  o     o  )__/       kitteh! demands obedience...
```

Obey the kitteh 😼
"""
import argparse
import os

import ofrak_ghidra
from ofrak import OFRAK, OFRAKContext, ResourceFilter, ResourceAttributeValueFilter
from ofrak.core import (
    BinaryPatchModifier,
    BinaryPatchConfig,
    CodeRegion,
    ComplexBlock,
    Instruction,
    LiefAddSegmentConfig,
    LiefAddSegmentModifier,
    ElfProgramHeader,
)

ASSETS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "assets"))
BINARY_FILE = os.path.join(ASSETS_DIR, "example_program")
KITTEH = rb"""
       | | | |  ___  | || |  ___   | | / /(_)  _     _
       | |_| | / _ \ | || | / _ \  | |/ /  _ _| |_ _| |_  _  _
       |  _  |/ /_\ \| || |/ / \ \ |   /  | |_   _|_   _|| |/ /
       | | | |\ ,___/| || |\ \_/ / | |\ \ | | | |_  | |_ | / /
       |_| |_| \___/ |_||_| \___/  |_| \_\|_| \___| \___||  /
                              _           _              / /
                             / \_______ /|_\             \/
                            /          /_/ \__
                           /             \_/ /
                         _|_              |/|_
                         _|_  O    _    O  _|_
                         _|_      (_)      _|_
                          \                 /
                           _\_____________/_
                          /  \/  (___)  \/  \
                          \__(  o     o  )__/       kitteh! demands obedience..."""
SEVEN_KITTEH = 7 * KITTEH + b"\x00"
PAGE_ALIGN = 0x1000


async def main(ofrak_context: OFRAKContext, file_path: str, output_file_name: str):
    root_resource = await ofrak_context.create_root_resource_from_file(file_path)

    # Add a segment
    empty_vaddr = 0x108000
    config = LiefAddSegmentConfig(empty_vaddr, PAGE_ALIGN, [0 for _ in range(0x2000)], "rw")
    await root_resource.run(LiefAddSegmentModifier, config)
    await root_resource.unpack_recursively(do_not_unpack=(CodeRegion,))

    file_segments = await root_resource.get_descendants_as_view(
        ElfProgramHeader, r_filter=ResourceFilter(tags=(ElfProgramHeader,))
    )
    new_segment = [seg for seg in file_segments if seg.p_vaddr == empty_vaddr].pop()
    kitty_bytes_offset = new_segment.p_offset

    # Add KITTEH to the new segment
    patch_config = BinaryPatchConfig(kitty_bytes_offset, SEVEN_KITTEH)
    await root_resource.run(BinaryPatchModifier, patch_config)

    # Hello world is being loaded by a lea instruction.
    # Let's point it to load from the new entry point instead!
    await root_resource.unpack_recursively()
    main_cb = await root_resource.get_only_descendant_as_view(
        v_type=ComplexBlock,
        r_filter=ResourceFilter(
            attribute_filters=(ResourceAttributeValueFilter(ComplexBlock.Symbol, "main"),)
        ),
    )
    main_cb_assembly = await main_cb.get_assembly()
    lea_instruction = await main_cb.resource.get_only_descendant_as_view(
        v_type=Instruction,
        r_filter=ResourceFilter(
            attribute_filters=(ResourceAttributeValueFilter(Instruction.Mnemonic, "lea"),)
        ),
    )
    ghidra_empty_vaddr = empty_vaddr + 0x100000  # Ghidra bases PIE executables at 0x100000
    kitty_offset = ghidra_empty_vaddr - lea_instruction.virtual_address - 7
    await lea_instruction.modify_assembly("lea", f"rdi, [rip + {kitty_offset}]")

    await root_resource.pack()
    await root_resource.flush_to_disk(output_file_name)
    print(f"Done! Output file written to {output_file_name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--hello-world-file", default=BINARY_FILE)
    parser.add_argument("--output-file-name", default="./example_5_kitteh")
    args = parser.parse_args()

    ofrak = OFRAK()
    ofrak.discover(ofrak_ghidra)
    ofrak.run(main, args.hello_world_file, args.output_file_name)
