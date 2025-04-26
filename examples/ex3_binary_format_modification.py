"""
This example showcases the power of OFRAK in analyzing, and contextually modifying complex binary
formats, in this case an ELF executable!

The input program is a compiled binary ELF file which prints "Hello, World!" to the console.

```c
#include <stdio.h>
int main() {
   printf("Hello, World!\n");
   return 0;
}
```

The example analyzes the ELF headers and changes the permissions for the LOAD program header,
marking the section as non-executable.

wat do u mean program no run?? 😿
"""
import argparse
import os

from ofrak import OFRAK, OFRAKContext
from ofrak.core import (
    Elf,
    ElfProgramHeader,
    ElfProgramHeaderType,
    ElfProgramHeaderModifier,
    ElfProgramHeaderModifierConfig,
)
from ofrak_type.memory_permissions import MemoryPermissions

ASSETS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "assets"))
BINARY_FILE = os.path.join(ASSETS_DIR, "example_program")


def main(ofrak_context: OFRAKContext, file_path: str, output_file_name: str):
    root_resource = ofrak_context.create_root_resource_from_file(file_path)
    root_resource.unpack()

    elf_v = root_resource.view_as(Elf)
    exec_load_program_header = get_exec_load_program_header(elf_v)

    # Make this program header non-executable
    exec_load_program_header.resource.run(
        ElfProgramHeaderModifier,
        ElfProgramHeaderModifierConfig(
            p_flags=exec_load_program_header.p_flags & ~MemoryPermissions.X.value
        ),
    )

    # Dump the modified program to disk
    root_resource.pack()
    root_resource.flush_data_to_disk(output_file_name)
    print(f"Done! Output file written to {output_file_name}")


def get_exec_load_program_header(elf_v: Elf) -> ElfProgramHeader:
    """Return the first executable LOAD program header in `elf_view`."""
    for program_header in elf_v.get_program_headers():
        if (
            program_header.p_type == ElfProgramHeaderType.LOAD.value
            and program_header.p_flags & MemoryPermissions.X.value
        ):
            return program_header
    raise RuntimeError(f"Could not find executable LOAD program header in {elf_v}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--hello-world-file", default=BINARY_FILE)
    parser.add_argument("--output-file-name", default="./example_3_segmeow")
    args = parser.parse_args()

    ofrak = OFRAK()
    ofrak.run(main, args.hello_world_file, args.output_file_name)
