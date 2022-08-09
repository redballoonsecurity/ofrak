"""
This example showcases the simplicity of performing string modifications with OFRAK.

The input program is a compiled binary ELF file which prints "Hello, World!" to the console.

```c
#include <stdio.h>
int main() {
   printf("Hello, World!\n");
   return 0;
}
```

The example directly modifies the "Hello, World" string and replaces it with something a bit more
fun and furry 😼. Meow!
"""
import argparse
import os

from ofrak import OFRAK
from ofrak import OFRAKContext
from ofrak.core import BinaryPatchModifier, BinaryPatchConfig

ASSETS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "assets"))
BINARY_FILE = os.path.join(ASSETS_DIR, "example_program")


async def main(ofrak_context: OFRAKContext, file_path: str, output_file_name: str):
    # Load a binary file into OFRAK as a resource
    root_resource = await ofrak_context.create_root_resource_from_file(file_path)

    # Get the raw bytes from the resource
    data = await root_resource.get_data()

    # Find the "Hello, World!" byte string in the data
    hello_world_offset = data.find(b"Hello, World!")

    # Patch the binary by writing the null-terminated string "Meow!" over
    # the first occurrence of "Hello, World!" using the BinaryPatchModifier
    new_string_config = BinaryPatchConfig(hello_world_offset, b"Meow!\0")
    await root_resource.run(BinaryPatchModifier, new_string_config)

    # Output the modified binary to the disk
    await root_resource.flush_to_disk(output_file_name)
    print(f"Done! Output file written to {output_file_name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--hello-world-file", default=BINARY_FILE)
    parser.add_argument("--output-file-name", default="./example_1_meow")
    args = parser.parse_args()

    # First we set up OFRAK
    ofrak = OFRAK()

    # Then, we run the main function to perform the patch. Note that ofrak.run handles the
    # async/await machinery for us
    ofrak.run(main, args.hello_world_file, args.output_file_name)
