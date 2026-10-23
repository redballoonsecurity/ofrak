"""
This example carries reverse-engineering markup (function names and comments) from one build of a
program to another, headlessly, with anchor-based markup and portable RE annotations.

The two builds are the stand-alone Lua 5.4.7 interpreter compiled by GCC 11 (build A) and by
GCC 15 (build B), both stripped: the pair OFRAK's own tests use. Nearly every function is at a
different address in build B, so markup recorded by address would land on the wrong functions.
Instead:

1. Functions of build A are named and commented from an anchor set: each anchor finds its
   function by a string literal the function references, such as

    ```yaml
    - name: luaL_argerror
      value: "bad argument #%d to '%s' (%s)"
      comment: Raises the standard error for a bad argument to a C function.
    ```

   An anchor that matches several functions is reported as ambiguous and not applied.
2. The markup of build A is exported to a portable, git-diffable JSON document, which identifies
   each function by the strings it references (and by its code, if unchanged) instead of by its
   address.
3. The document is imported onto build B, where each record is applied to the one function that
   matches its fingerprint; records without a unique match are reported, never force-applied.
4. Build B is packed and written back to disk, as at the end of any OFRAK pipeline. The markup is
   metadata, so the binary comes out unchanged; a pipeline would patch the functions it can now
   find by name before repacking.

This needs the Ghidra backend (`python -m ofrak_ghidra.server start`), which provides the data
cross-references the string references are derived from. Analyzing both builds takes a couple of
minutes.
"""
import argparse
import os

import ofrak_ghidra
from ofrak import OFRAK, OFRAKContext
from ofrak.core import (
    AnchorResolutionReport,
    ApplyAnchoredMarkupModifier,
    CommentsAttributes,
    MarkupImportConfig,
    MarkupImportModifier,
    MarkupImportReport,
    Program,
    export_portable_markup,
    load_anchor_set,
    load_portable_markup,
    save_portable_markup,
)

ASSETS_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__), "..", "ofrak_core", "tests", "components", "assets", "re_markup"
    )
)
BUILD_A = os.path.join(ASSETS_DIR, "lua-gcc11-O2")
BUILD_B = os.path.join(ASSETS_DIR, "lua-gcc15-O2")
ANCHOR_SET = os.path.join(ASSETS_DIR, "lua-anchors.yml")


async def main(
    ofrak_context: OFRAKContext,
    build_a: str,
    build_b: str,
    anchor_set: str,
    output_file_name: str,
    output_binary: str,
):
    # Name and comment functions of build A with the anchor set
    build_a_resource = await ofrak_context.create_root_resource_from_file(build_a)
    await build_a_resource.unpack()
    await build_a_resource.run(ApplyAnchoredMarkupModifier, await load_anchor_set(anchor_set))
    anchor_report = build_a_resource.get_attributes(AnchorResolutionReport)
    for name, vaddrs in anchor_report.hits.items():
        print(f"Build A: anchored {name} at {hex(vaddrs[0])}")
    for name in anchor_report.misses:
        print(f"Build A: no function references the string of anchor {name}")
    for name, vaddrs in anchor_report.ambiguous.items():
        print(f"Build A: anchor {name} matches {len(vaddrs)} functions, so it was not applied")

    # Export the markup of build A to a portable document
    program_a = await build_a_resource.view_as(Program)
    markup = await export_portable_markup(program_a, os.path.basename(build_a))
    await save_portable_markup(ofrak_context, markup, output_file_name)
    marked_up = [function for function in markup.functions if function.has_markup()]
    print(f"Exported the markup of {len(marked_up)} functions to {output_file_name}")

    # Import the document onto build B. Analyzing build B replaces the analysis of build A in the
    # Ghidra backend, which is fine: everything needed from build A is in the document.
    build_b_resource = await ofrak_context.create_root_resource_from_file(build_b)
    await build_b_resource.unpack()
    markup = await load_portable_markup(ofrak_context, output_file_name)
    await build_b_resource.run(MarkupImportModifier, MarkupImportConfig(markup))
    import_report = build_b_resource.get_attributes(MarkupImportReport)
    for match in import_report.matched:
        print(
            f"Build B: imported {match.name} at {hex(match.function_vaddrs[0])} "
            f"(similarity {match.similarity:.2f})"
        )
    for match in import_report.ambiguous + import_report.unmatched:
        print(f"Build B: did not find {match.name}")

    # The imported markup is an ordinary name and comment of build B's function
    program_b = await build_b_resource.view_as(Program)
    argerror = await program_b.get_function_complex_block("luaL_argerror")
    comments = argerror.resource.get_attributes(CommentsAttributes).comments[None]
    print(f"Build B: {argerror.name} at {hex(argerror.virtual_address)}: {comments[0]}")

    # Repack build B and write it out
    await build_b_resource.pack_recursively()
    await build_b_resource.flush_data_to_disk(output_binary)
    with open(build_b, "rb") as original, open(output_binary, "rb") as repacked:
        unchanged = original.read() == repacked.read()
    print(f"Repacked build B to {output_binary}: {'unchanged' if unchanged else 'changed'}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-a", default=BUILD_A)
    parser.add_argument("--build-b", default=BUILD_B)
    parser.add_argument("--anchor-set", default=ANCHOR_SET)
    parser.add_argument("--output-file-name", default="./example_10_markup.json")
    parser.add_argument("--output-binary", default="./example_10_lua")
    args = parser.parse_args()

    ofrak = OFRAK()
    ofrak.discover(ofrak_ghidra)
    ofrak.run(
        main,
        args.build_a,
        args.build_b,
        args.anchor_set,
        args.output_file_name,
        args.output_binary,
    )
