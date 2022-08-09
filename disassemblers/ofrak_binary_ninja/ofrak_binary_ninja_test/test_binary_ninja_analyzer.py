from dataclasses import dataclass
from typing import Tuple

import pytest

from ofrak import OFRAKContext
from ofrak.core.filesystem import File
from ofrak_binary_ninja.components.binary_ninja_analyzer import BinaryNinjaAnalyzer
from ofrak_binary_ninja.model import BinaryNinjaAnalysis
from test_ofrak.unit.component.analyzer.analyzer_test_case import PopulatedAnalyzerTestCase


@dataclass
class PopulatedBinaryNinjaAnalyzerTestCase(PopulatedAnalyzerTestCase):
    resource_contents: bytes


@pytest.fixture()
async def test_case(
    hello_world_elf, ofrak_context: OFRAKContext, test_id: str
) -> PopulatedBinaryNinjaAnalyzerTestCase:
    resource = await ofrak_context.create_root_resource(test_id, hello_world_elf, tags=(File,))
    return PopulatedBinaryNinjaAnalyzerTestCase(
        BinaryNinjaAnalyzer,
        Tuple[BinaryNinjaAnalysis],
        ofrak_context,
        resource,
        hello_world_elf,
    )


async def test_binary_ninja_analyzer(test_case: PopulatedBinaryNinjaAnalyzerTestCase):
    """
    Test that the [BinaryNinjaAnalysis][ofrak_binary_ninja.model.BinaryNinjaAnalysis]
    object can be successfully generated
    """
    await test_case.resource.identify()
    analysis = await test_case.resource.analyze(BinaryNinjaAnalysis)
    assert isinstance(analysis, BinaryNinjaAnalysis)
