"""
Generate the code reference pages and navigation for ofrak, ofrak_patch_maker,
ofrak_toolchain.

This file is inspired by: https://github.com/mkdocstrings/pytkdocs/blob/master/docs/gen_ref_nav.py.
"""

from pathlib import Path
from typing import List

import mkdocs_gen_files
import yaml

# Selection configuration, will be serialized as YAML. See here for configuration options:
# https://mkdocstrings.github.io/handlers/python/#selection
SELECTIONS = {}

animals = list(Path("docs/assets").glob("square_*.png"))


def indent(s, num_spaces):
    """
    Indent every line of s by num_spaces spaces
    """
    return ("\n" + " " * num_spaces).join(s.splitlines())


def generate_docs(packages: List[str], directory: str):
    total_pages = 0
    for package in packages:
        for path in sorted(Path(f"{directory}/{package}").glob("**/*.py")):
            if (
                path.name.startswith("__init__")
                or path.name.startswith("_bind_dependencies")
                or path.name.startswith("_auto_attributes")
            ):
                continue
            module_path = path.relative_to(directory).with_suffix("")
            doc_path = path.relative_to(directory).with_suffix(".md")
            full_doc_path = Path("reference", doc_path)

            parts = list(module_path.parts)
            parts[-1] = f"{parts[-1]}.py"
            nav[parts] = doc_path

            with mkdocs_gen_files.open(full_doc_path, "w") as fd:
                ident = ".".join(module_path.parts)
                print("::: " + ident, file=fd)
                if ident in SELECTIONS:
                    print("    selection:", end="\n      ", file=fd)
                    print(indent(yaml.dump(SELECTIONS[ident]), 6), file=fd)

                # Build relative path to assets directory
                animal_path = ("../" * len(module_path.parts)) / (
                    animals[total_pages % len(animals)].relative_to("docs")
                )
                total_pages += 1
                print(
                    f"\n\n" f'<div align="right">\n',
                    f'<img width="125" height="125" src="{animal_path}">\n',
                    f"</div>\n",
                    file=fd,
                )

            mkdocs_gen_files.set_edit_path(full_doc_path, path)


nav = mkdocs_gen_files.Nav()
generate_docs(["ofrak"], "ofrak_core")
generate_docs(["ofrak_io"], "ofrak_io")
generate_docs(["ofrak_patch_maker"], "ofrak_patch_maker")
generate_docs(["ofrak_type"], "ofrak_type")
generate_docs(["ofrak_ghidra"], "disassemblers/ofrak_ghidra")


# Add generated files to reference/SUMMARY.md. mkdocs.yml uses this to display these docs.
with mkdocs_gen_files.open("reference/SUMMARY.md", "w") as nav_file:
    nav_file.writelines(nav.build_literate_nav())
