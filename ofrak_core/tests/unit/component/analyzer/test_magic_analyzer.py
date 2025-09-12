from dataclasses import dataclass

import pytest
from .analyzer_test_case import (
    AnalyzerTestCase,
    PopulatedAnalyzerTestCase,
    AnalyzerTests,
)

from ofrak import OFRAKContext
from ofrak.resource import Resource
from ofrak.core.magic import Magic, MagicAnalyzer


@dataclass
class MagicAnalyzerTestCase(AnalyzerTestCase):
    resource_contents: bytes


@dataclass
class PopulatedMagicAnalyzerTestCase(PopulatedAnalyzerTestCase, MagicAnalyzerTestCase):
    ofrak_context: OFRAKContext
    resource: Resource

    def get_analyzer(self):
        return self.ofrak_context.component_locator.get_by_type(self.analyzer_type)


@pytest.fixture(
    params=[
        MagicAnalyzerTestCase(MagicAnalyzer, Magic("text/plain", "ASCII text"), b"Hello world\n")
    ]
)
async def test_case(
    request, ofrak_context: OFRAKContext, test_id: str
) -> PopulatedMagicAnalyzerTestCase:
    test_case: MagicAnalyzerTestCase = request.param
    resource = await ofrak_context.create_root_resource(test_id, test_case.resource_contents)
    return PopulatedMagicAnalyzerTestCase(
        test_case.analyzer_type,
        test_case.expected_result,
        test_case.resource_contents,
        ofrak_context,
        resource,
    )


class TestMagicAnalyzer(AnalyzerTests):
    pass
