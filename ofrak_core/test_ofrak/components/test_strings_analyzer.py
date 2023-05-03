from dataclasses import dataclass

from ofrak.service.component_locator_i import ComponentLocatorInterface
from ofrak_type.error import NotFoundError

import pytest

from synthol.injector import DependencyInjector
from test_ofrak.unit.component.analyzer.analyzer_test_case import (
    AnalyzerTestCase,
    PopulatedAnalyzerTestCase,
    AnalyzerTests,
)

from ofrak.ofrak_context import OFRAKContext
from ofrak.core.strings_analyzer import StringsAnalyzer, StringsAttributes


@dataclass
class StringsAnalyzerTestCase(AnalyzerTestCase):
    resource_contents: bytes


@dataclass
class PopulatedStringsAnalyzerTestCase(PopulatedAnalyzerTestCase, StringsAnalyzerTestCase):
    pass


@pytest.fixture(
    params=[
        StringsAnalyzerTestCase(
            StringsAnalyzer, StringsAttributes({0: "Hello world"}), b"Hello world\n"
        )
    ]
)
async def test_case(
    request, ofrak_context: OFRAKContext, test_id: str, ofrak_injector: DependencyInjector
) -> PopulatedStringsAnalyzerTestCase:
    test_case: StringsAnalyzerTestCase = request.param
    resource = await ofrak_context.create_root_resource(test_id, test_case.resource_contents)
    component_locator = await ofrak_injector.get_instance(ComponentLocatorInterface)
    return PopulatedStringsAnalyzerTestCase(
        test_case.analyzer_type,
        test_case.expected_result,
        test_case.resource_contents,
        component_locator,
        resource,
    )


class TestStringsAnalyzer(AnalyzerTests):
    async def test_resource_analyzer(self, test_case: PopulatedAnalyzerTestCase):
        with pytest.raises(
            NotFoundError, match="Unable to find any analyzer for attributes StringsAttributes"
        ):
            await super().test_resource_analyzer(test_case)
