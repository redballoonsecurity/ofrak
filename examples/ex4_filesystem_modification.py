"""
This example collates previous examples, and additionally demonstrates the filesystem unpacking
capabilities of OFRAK.

The input to this example is a SquashFS filesystem which includes our boring old "Hello, World!"
program in it:

```c
#include <stdio.h>
int main() {
   printf("Hello, World!\n");
   return 0;
}
```

The example unpacks the SquashFS input, and analyzes each of its contents including the "Hello,
World!" program. For that program it modifies the "Hello, World!" string, replacing it with
something even more fun and furry 😼😼. More Meow! Finally, the example modifies the executable's
permission bits and extended attributes as part of the SquashFS filesystem, before repacking it.
"""
import argparse
import os
import stat

from ofrak import OFRAK, OFRAKContext
from ofrak.core import BinaryPatchConfig, BinaryPatchModifier
from ofrak.core.squashfs import SquashfsFilesystem

ASSETS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "assets"))
SQUASHFS_FILE = os.path.join(ASSETS_DIR, "sample.sqsh")


async def main(ofrak_context: OFRAKContext, file_path: str, output_file_name: str):
    # Create resource
    root_resource = await ofrak_context.create_root_resource_from_file(file_path)

    # Unpack resource
    await root_resource.unpack_recursively()
    # Get the program from inside the SquashFS filesystem
    squashfs_view = await root_resource.view_as(SquashfsFilesystem)
    hello_world_program_path = "src/program"
    hello_world_program = await squashfs_view.get_entry(hello_world_program_path)

    # Get the "Hello, World!" string location in the program and patch it with "More meow!"
    program_data = await hello_world_program.resource.get_data()
    hello_world_offset = program_data.find(b"Hello, World!")

    new_string_config = BinaryPatchConfig(hello_world_offset, b"More meow!\0")
    await hello_world_program.resource.run(BinaryPatchModifier, new_string_config)

    # Modify the program permission bits and xattrs before repacking
    print(f"Initial st_mode: {hello_world_program.stat.st_mode:o}")
    print(f"Initial xattrs: {hello_world_program.xattrs}")

    await hello_world_program.modify_stat_attribute(stat.ST_MODE, 0o100755)
    await hello_world_program.modify_xattr_attribute("user.foo", b"bar")

    print(f"Modified st_mode: {hello_world_program.stat.st_mode:o}")
    print(f"Modified xattrs: {hello_world_program.xattrs}")

    # Dump the repacked file to the disk
    await root_resource.pack()
    await root_resource.flush_data_to_disk(output_file_name)
    print(f"Done! Output file written to {output_file_name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--hello-world-file", default=SQUASHFS_FILE)
    parser.add_argument("--output-file-name", default="./example_4_more_meow.sqsh")
    args = parser.parse_args()

    ofrak = OFRAK()
    ofrak.run(main, args.hello_world_file, args.output_file_name)
