"""
Tests for `FlashGeometryHeuristicAnalyzer`: verify it infers `FlashAttributes` from synthetic
raw NAND dumps tagged as `FlashResource`, covering every default geometry, and that it returns
no attributes (rather than raising) when the file size doesn't match any standard geometry.

We are not using the existing flash test assets because the heuristics rely on attributes
you might expect to see in real NAND dumps, such as YAFFS2 tags, Linux MTD large-page OOB.
Test assets are not representative of real NAND dumps.

Requirements Mapping:
- REQ2.1
- REQ2.2
"""
import random
import struct
from dataclasses import dataclass
from typing import List, Tuple

import pytest

from ofrak import OFRAKContext
from ofrak.core.flash import FlashAttributes, FlashField, FlashFieldType, FlashResource
from ofrak_type.error import NotFoundError
from ofrak.core.flash.analyzer import FlashGeometryHeuristicAnalyzer
from ofrak.core.flash.heuristics import (
    LINUX_MTD_OOB_ECC_END,
    LINUX_MTD_OOB_ECC_OFFSET,
    SMALL_PAGE_BBM_OFFSET,
    SMALL_PAGE_OOB_MAX,
    YAFFS2_PACKED_TAGS2_END,
    YAFFS2_PACKED_TAGS2_OFFSET,
    YAFFS2_TAG_MARKER_VALUE,
    _linux_mtd_hamming_ecc_256,
)
from ..unit.component.analyzer.analyzer_test_case import (
    AnalyzerTestCase,
    AnalyzerTests,
    PopulatedAnalyzerTestCase,
)


class SyntheticNand:
    @staticmethod
    def ecc_triplets(page_data: bytes) -> bytes:
        """
        Byte-exact Linux MTD soft-Hamming ECC for the first 8 * 256-byte sectors (24 bytes).

        The cap at 8 sectors is an analyzer-side heuristic, not a Linux convention: real Linux
        only uses this `nand_oob_64` soft-Hamming layout for 2K pages, whereas 4K/8K NAND
        typically uses BCH with a different OOB layout.
        """
        n_sectors = min(len(page_data) // 256, 8)
        return b"".join(
            _linux_mtd_hamming_ecc_256(page_data[s * 256 : (s + 1) * 256]) for s in range(n_sectors)
        )

    @staticmethod
    def small_page_oob(oob_size: int) -> bytes:
        """
        Synthesize a densely-populated small-page OOB (<=16 bytes)
        byte 5 (BBM) is 0xFF and every other byte is non-0xFF.
        """
        oob = bytearray(random.randbytes(oob_size))
        for i in range(oob_size):
            if i == SMALL_PAGE_BBM_OFFSET:
                continue
            if oob[i] == 0xFF:
                oob[i] = 0xFE
        if oob_size > SMALL_PAGE_BBM_OFFSET:
            oob[SMALL_PAGE_BBM_OFFSET] = 0xFF
        return bytes(oob)

    @staticmethod
    def large_page_oob(page_idx: int, data: bytes, oob_size: int) -> bytes:
        """
        Synthesize a large-page OOB (>=64 bytes). Odd-indexed pages use the YAFFS2 packed-tags-2
        layout; even-indexed pages use the Linux MTD ECC-only layout. Every page carries the
        byte-exact Hamming ECC for its first 8 * 256 data bytes at OOB[40:64]. Remaining bytes
        beyond byte 64 are 0xFF padding.
        """
        oob = bytearray(b"\xff" * oob_size)
        if page_idx % 2 == 1:
            oob[1] = YAFFS2_TAG_MARKER_VALUE
            # Packed tags 2: (seq_number, object_id, chunk_id, n_bytes). `n_bytes` must be in
            # (0, data_size] to be accepted by `Yaffs2PackedTagsHeuristic`.
            oob[YAFFS2_PACKED_TAGS2_OFFSET:YAFFS2_PACKED_TAGS2_END] = struct.pack(
                "<IIII", page_idx + 1, 100 + page_idx, page_idx, max(1, len(data) // 2)
            )
        oob[LINUX_MTD_OOB_ECC_OFFSET:LINUX_MTD_OOB_ECC_END] = SyntheticNand.ecc_triplets(data)
        return bytes(oob)

    @staticmethod
    def build(data_size: int, oob_size: int, num_pages: int) -> bytes:
        """
        Build a raw NAND image of `num_pages` physical pages sized `(data_size + oob_size)` each.
        Relies on the module-level `random` state; seed via the `_seeded_random` fixture.
        """
        pages: List[bytes] = []
        for i in range(num_pages):
            data = random.randbytes(data_size)
            if oob_size == 0:
                oob = b""
            elif oob_size <= SMALL_PAGE_OOB_MAX:
                oob = SyntheticNand.small_page_oob(oob_size=oob_size)
            else:
                oob = SyntheticNand.large_page_oob(page_idx=i, data=data, oob_size=oob_size)
            pages.append(data + oob)
        return b"".join(pages)


def _expected_attrs(data_size: int, oob_size: int) -> Tuple[FlashAttributes, ...]:
    return (
        FlashAttributes(
            data_block_format=[
                FlashField(FlashFieldType.DATA, data_size),
                FlashField(FlashFieldType.SPARE, oob_size),
            ]
        ),
    )


# Parameterized test cases: one per default geometry. `num_pages` is always a power of two,
# kept small to keep each image under 20 KB.
GEOMETRY_CASES: Tuple[Tuple[int, int, int, str], ...] = (
    (2048, 64, 8, "large_page_2048_64"),
    (4096, 128, 4, "large_page_4096_128"),
    (512, 16, 16, "small_page_512_16"),
    (4096, 224, 2, "large_page_4096_224"),
    (8192, 448, 2, "large_page_8192_448"),
    (256, 0, 8, "raw_no_oob_256_0"),
)


@dataclass
class FlashGeometryHeuristicAnalyzerTestCase(AnalyzerTestCase):
    resource_contents: bytes


@dataclass
class PopulatedFlashGeometryHeuristicAnalyzerTestCase(
    PopulatedAnalyzerTestCase, FlashGeometryHeuristicAnalyzerTestCase
):
    pass


@pytest.fixture
def _seeded_random():
    """Seed the module-level `random` state so synthetic NAND builds are reproducible."""
    random.seed(0xA5A5B00B)


@pytest.fixture(
    params=GEOMETRY_CASES,
    ids=[case_id for *_rest, case_id in GEOMETRY_CASES],
)
async def test_case(
    request, _seeded_random, ofrak_context: OFRAKContext, test_id: str
) -> PopulatedFlashGeometryHeuristicAnalyzerTestCase:
    data_size, oob_size, num_pages, _id = request.param
    resource_contents = SyntheticNand.build(data_size, oob_size, num_pages)
    resource = await ofrak_context.create_root_resource(
        test_id, resource_contents, tags=(FlashResource,)
    )
    return PopulatedFlashGeometryHeuristicAnalyzerTestCase(
        FlashGeometryHeuristicAnalyzer,
        _expected_attrs(data_size, oob_size),
        resource_contents,
        ofrak_context,
        resource,
    )


class TestFlashGeometryHeuristicAnalyzer(AnalyzerTests):
    """Run the standard `AnalyzerTests` suite against the heuristic analyzer (REQ2.1)."""


async def test_no_matching_geometry_returns_no_attrs(ofrak_context: OFRAKContext, test_id: str):
    """
    Verify the analyzer degrades gracefully for a file whose size doesn't evenly divide any
    standard NAND geometry into a power-of-two page count: it logs a warning and returns no
    attributes instead of raising, so other analyzers (e.g. `BinwalkAnalyzer`) can still run
    on the same resource (REQ2.2).
    """
    resource = await ofrak_context.create_root_resource(
        test_id, b"\x00" * 257, tags=(FlashResource,)
    )
    with pytest.raises(NotFoundError):
        await resource.analyze(FlashAttributes)
