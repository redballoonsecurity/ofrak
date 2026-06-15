"""
This example demonstrates how to use the flash component to unpack, modify, and repack a raw flash dump.
The included dump has ECC data mixed in with useful data.
We want to strip out the ECC then modify the data before repacking.
"""
import argparse
import os

from ofrak import OFRAK, OFRAKContext, ResourceFilter
from ofrak.core.binary import BinaryPatchConfig, BinaryPatchModifier
from ofrak.core.flash import (
    FlashAttributes,
    FlashEccAttributes,
    FlashField,
    FlashFieldType,
    FlashResource,
    FlashLogicalDataResource,
)
from ofrak.core.ecc.reedsolomon import ReedSolomon

ASSETS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "assets"))
TEST_FILE = os.path.join(ASSETS_DIR, "flash_test_plain.bin")
FLASH_ATTRIBUTES = FlashAttributes(
    data_block_format=[
        FlashField(FlashFieldType.DATA, 223),
        FlashField(FlashFieldType.ECC, 32),
    ],
    ecc_attributes=FlashEccAttributes(
        ecc_class=ReedSolomon(nsym=32),
    ),
)


async def main(ofrak_context: OFRAKContext, in_file: str, out_file: str):
    # Create root resource and tag
    root_resource = await ofrak_context.create_root_resource_from_file(in_file)
    root_resource.add_tag(FlashResource)
    await root_resource.save()

    # Add our attributes
    root_resource.add_attributes(FLASH_ATTRIBUTES)
    await root_resource.save()

    # Unpack
    await root_resource.unpack_recursively()
    print(f"Unpacked:\n{await root_resource.summarize_tree()}")

    # Get the logical data
    logical_data_resource = await root_resource.get_only_descendant(
        r_filter=ResourceFilter.with_tags(FlashLogicalDataResource),
    )

    # Modify the logical data
    new_data = b"INSERT ME!"
    patch_config = BinaryPatchConfig(0x16, new_data)
    await logical_data_resource.run(BinaryPatchModifier, patch_config)

    # Repack and save to disk
    await root_resource.flush_data_to_disk(out_file)
    print(f"Saved repacked dump to {out_file}!")
    print(await root_resource.summarize_tree())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-file", default=TEST_FILE)
    parser.add_argument("--output-file", default="./repacked_flash_dump.bin")
    args = parser.parse_args()

    ofrak = OFRAK()
    ofrak.run(main, args.input_file, args.output_file)
