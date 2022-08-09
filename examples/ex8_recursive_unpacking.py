"""
This example showcases the automatic recursive unpacking capabilities of OFRAK.

The input to this example is a nested tar.gz including a "Hello, world!" text file:
```text
└── example_8.tar.gz
    └── example_8_inner.tar.gz
        └── hello_world.txt
```

The example automatically and recursively unpacks the input, and adds a new text file with an
obedience-demanding kitteh (😼(😼(😼))). The resulting output looks like:
```text
└── example_8_meow.tar.gz
    └── example_8_inner.tar.gz
        ├── hello_world.txt
        └── meow.txt
```
"""
import argparse
import os

from ofrak import OFRAK, OFRAKContext
from ofrak_components.tar import TarArchive

ASSETS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "assets"))
ARCHIVE = os.path.join(ASSETS_DIR, "example_8.tar.gz")
KITTEH = r"""
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


async def main(ofrak_context: OFRAKContext, file_path: str, output_file_name: str):
    # Load a root resource from the input file
    root_resource = await ofrak_context.create_root_resource_from_file(file_path)

    # Let OFRAK automatically unpack the file
    await root_resource.unpack_recursively()

    # Step through the filesystem hierarchy to the innermost TAR
    outer_tar = await root_resource.get_only_child()
    inner_gzip = await outer_tar.get_only_child()
    inner_tar = await inner_gzip.get_only_child()

    # View the innermost TAR as a TarArchive so that we can access TAR-specific methods
    tar_view = await inner_tar.view_as(TarArchive)

    # Add a file
    await tar_view.add_file("meow.txt", KITTEH.encode("ascii"))

    # Repack the file automagically and save the repacked file to disk
    await root_resource.pack_recursively()
    await root_resource.flush_to_disk(output_file_name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive-file", default=ARCHIVE)
    parser.add_argument("--output-file-name", default="./example_8_meow.tar.gz")
    args = parser.parse_args()

    ofrak = OFRAK()
    ofrak.run(main, args.archive_file, args.output_file_name)
