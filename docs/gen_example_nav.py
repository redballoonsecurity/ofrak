"""
Generate the code reference pages and navigation for the examples.

This file is inspired by: https://github.com/mkdocstrings/pytkdocs/blob/master/docs/gen_ref_nav.py.
"""
import re
from pathlib import Path

import mkdocs_gen_files

animals = list(Path("docs/assets").glob("square_*.png"))

example_nav = mkdocs_gen_files.Nav()
r = re.compile(r"^ex(\d+)", re.IGNORECASE)

for i, path in enumerate(sorted(Path("examples").glob("**/ex*.py"))):
    module_path = path.relative_to("examples").with_suffix("")
    doc_path = path.relative_to("examples").with_suffix(".md")

    parts = list(module_path.parts)
    parts[-1] = parts[-1].replace("_", " ")
    parts[-1] = r.sub(r"Example \1:", parts[-1]).title()
    example_nav[tuple(parts)] = str(doc_path)

    with open(path) as f:
        code = f.read().strip()
    if code.startswith('"""'):
        close_quotes = code[3:].find('"""') + 3
        docstring = code[3:close_quotes]
        code = code[close_quotes + 3 :]
    else:
        docstring = ""

    with mkdocs_gen_files.open(Path("examples", doc_path), "w") as f:
        # Build relative path to assets directory
        animal_path = ("../" * len(module_path.parts)) / (
            animals[i % len(animals)].relative_to("docs")
        )
        print(
            f"\n{docstring}\n\n"
            f"---\n\n"
            f"Example OFRAK script:\n\n"
            f'```python linenums="{len(docstring.splitlines()) + 2}"\n'
            f"{code}\n"
            f"```\n\n"
            f'<div align="right">\n',
            f'<img width="125" height="125" src="{animal_path}">\n',
            f"</div>\n",
            file=f,
        )

with mkdocs_gen_files.open("examples/SUMMARY.md", "w") as f:
    f.writelines(example_nav.build_literate_nav())
