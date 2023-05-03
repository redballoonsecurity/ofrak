from dataclasses import dataclass

import pytest

from ofrak.service.component_locator_i import ComponentLocatorInterface
from synthol.injector import DependencyInjector
from test_ofrak.unit.component.analyzer.analyzer_test_case import (
    AnalyzerTestCase,
    PopulatedAnalyzerTestCase,
    AnalyzerTests,
)

from ofrak import OFRAKContext
from ofrak.core.magic import Magic, MagicAnalyzer


@dataclass
class MagicAnalyzerTestCase(AnalyzerTestCase):
    resource_contents: bytes


@dataclass
class PopulatedMagicAnalyzerTestCase(PopulatedAnalyzerTestCase, MagicAnalyzerTestCase):
    pass


@pytest.fixture(
    params=[
        MagicAnalyzerTestCase(MagicAnalyzer, Magic("text/plain", "ASCII text"), b"Hello world\n")
    ]
)
async def test_case(
    request, ofrak_context: OFRAKContext, test_id: str, ofrak_injector: DependencyInjector
) -> PopulatedMagicAnalyzerTestCase:
    test_case: MagicAnalyzerTestCase = request.param
    resource = await ofrak_context.create_root_resource(test_id, test_case.resource_contents)
    component_locator = await ofrak_injector.get_instance(ComponentLocatorInterface)
    return PopulatedMagicAnalyzerTestCase(
        test_case.analyzer_type,
        test_case.expected_result,
        test_case.resource_contents,
        component_locator,
        resource,
    )


class TestMagicAnalyzer(AnalyzerTests):
    pass
