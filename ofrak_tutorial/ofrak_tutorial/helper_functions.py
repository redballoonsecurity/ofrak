"""
Helper functions for the OFRAK tutorial.

Useful since the tutorial is split into multiple notebooks, which can't easily import previous notebooks and don't
assume they have already been run either.

Importing this file also has the side effect of changing the current working directory to /tmp.
"""

import os

HELLO_WORLD_SOURCE = r"""
#include <stdio.h>
int main() {
   printf("Hello, World!\n");
   return 0;
}
"""


# Side effect: change the current working directory to /tmp
os.chdir("/tmp")


def create_binary(c_program: str, executable_filename: str) -> None:
    """Compile `c_program` into a binary at `executable_filename`."""
    c_source_filename = f"{executable_filename}.c"
    with open(c_source_filename, "w") as f:
        f.write(c_program)

    # -no-pie is used to circumvent a current limitation of our Ghidra integration
    os.system(f"gcc -no-pie -o {executable_filename} {c_source_filename}")


def create_hello_world_binary() -> None:
    """Create a simple binary printing "Hello, World!\n" to stdout."""
    create_binary(HELLO_WORLD_SOURCE, "hello_world")


async def get_descendants_tags(resource):
    """Return an alphabetically sorted list of all the tags of the descendants of `resource`."""
    all_tags = set()
    for child_resource in await resource.get_descendants():
        all_tags |= set(child_resource.get_tags())
    return sorted(all_tags, key=str)
