from dataclasses import dataclass

import pytest

from test_ofrak.unit.component.analyzer.analyzer_test_case import (
    AnalyzerTestCase,
    PopulatedAnalyzerTestCase,
    AnalyzerTests,
)

from ofrak.ofrak_context import OFRAKContext
from ofrak.resource import Resource
from ofrak_components.strings_analyzer import StringsAnalyzer, StringsAttributes


@dataclass
class StringsAnalyzerTestCase(AnalyzerTestCase):
    resource_contents: bytes


@dataclass
class PopulatedStringsAnalyzerTestCase(PopulatedAnalyzerTestCase, StringsAnalyzerTestCase):
    ofrak_context: OFRAKContext
    resource: Resource

    def get_analyzer(self):
        return self.ofrak_context.component_locator.get_by_type(self.analyzer_type)


@pytest.fixture(
    params=[
        StringsAnalyzerTestCase(
            StringsAnalyzer, StringsAttributes({0: "Hello world"}), b"Hello world\n"
        )
    ]
)
async def test_case(
    request, ofrak_context: OFRAKContext, test_id: str
) -> PopulatedStringsAnalyzerTestCase:
    test_case: StringsAnalyzerTestCase = request.param
    resource = await ofrak_context.create_root_resource(test_id, test_case.resource_contents)
    return PopulatedStringsAnalyzerTestCase(
        test_case.analyzer_type,
        test_case.expected_result,
        test_case.resource_contents,
        ofrak_context,
        resource,
    )


class TestStringsAnalyzer(AnalyzerTests):
    pass
