from dataclasses import dataclass
from typing import Dict, Optional

import os
import pytest

from ofrak.core.binwalk import BinwalkAnalyzer, BinwalkAttributes
import test_ofrak.components

BINWALK_ASSETS_PATH = os.path.join(test_ofrak.components.ASSETS_DIR, "binwalk_assets")


@dataclass
class BinwalkTestCase:
    filename: str
    # The expected length of the BinwalkAttributes dictionary, or None if the length shouldn't be
    # checked.
    number_of_results: Optional[int]
    # Subset of the expected BinwalkAttributes dictionary.
    subset_of_results: Dict[int, str]


BINWALK_TEST_CASES = [
    BinwalkTestCase(
        "dirtraversal.tar",
        1,
        {0: "POSIX tar archive (GNU)"},
    ),
    BinwalkTestCase(
        "firmware.zip",
        None,
        {
            0: "Zip archive data, at least v1.0 to extract, name: dir655_revB_FW_203NA/",
            6410581: "End of Zip archive, footer length: 22",
        },
    ),
    BinwalkTestCase(
        "foobar.lzma",
        1,
        {
            0: "LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: -1 bytes",
        },
    ),
    BinwalkTestCase(
        "firmware.squashfs",
        1,
        {
            0: (
                "Squashfs filesystem, little endian, version 4.0, compression:lzma, size: "
                "3647665 bytes, 1811 inodes, blocksize: 524288 bytes, created: 2013-09-17 06:43:22"
            )
        },
    ),
]


@pytest.mark.skipif_missing_deps([BinwalkAnalyzer])
@pytest.mark.parametrize("test_case", BINWALK_TEST_CASES, ids=lambda tc: tc.filename)
async def test_binwalk_component(ofrak_context, test_case):
    asset_path = os.path.join(BINWALK_ASSETS_PATH, test_case.filename)
    root_resource = await ofrak_context.create_root_resource_from_file(asset_path)
    await root_resource.analyze(BinwalkAttributes)
    binwalk_attributes = root_resource.get_attributes(BinwalkAttributes)
    binwalk_offsets = binwalk_attributes.offsets
    if test_case.number_of_results is not None:
        assert len(binwalk_offsets) == test_case.number_of_results
    assert test_case.subset_of_results.items() <= binwalk_offsets.items()
