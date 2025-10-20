"""
Test cases for the analyzer interface and validation of analyzers.

Requirements Mapping:
- REQ2.1
"""
from dataclasses import dataclass
from typing import Type

import pytest

from ofrak import OFRAKContext
from ofrak.component.analyzer import Analyzer, AnalyzerReturnType
from ofrak.model.component_model import CC
from ofrak.model.resource_model import ResourceAttributes
from ofrak.resource import Resource
from ofrak_type.error import NotFoundError


@dataclass
class DummyAttributes(ResourceAttributes):
    dummy_value: str


@dataclass
class AnalyzerTestCase:
    analyzer_type: Type[Analyzer[CC, AnalyzerReturnType]]
    expected_result: AnalyzerReturnType


@dataclass
class PopulatedAnalyzerTestCase(AnalyzerTestCase):
    ofrak_context: OFRAKContext
    resource: Resource

    def get_analyzer(self):
        return self.ofrak_context.component_locator.get_by_type(self.analyzer_type)


class AnalyzerTests:
    """
    A suite of tests that validates the output of analyzers.

    Contributors should subclass this test and create a `test_case` fixture to run these tests.
    """

    async def test_analyze_method(self, test_case: PopulatedAnalyzerTestCase):
        """
        Test that :func:`Analyzer.analyze` returns the expected AnalyzerReturnType (REQ2.1).

        This test verifies that:
        - The analyzer's analyze method result matches the expected result specified in the test
        case
        """
        analyzer = test_case.get_analyzer()
        result = await analyzer.analyze(test_case.resource)
        assert result == test_case.expected_result

    async def test_resource_analyzer(self, test_case: PopulatedAnalyzerTestCase):
        """
        Test that :func:`Resource.analyze` returns the expected resource attributes (REQ2.1).

        This test verifies that:
        - The resource's analyze method can retrieve the expected attributes
        """
        if isinstance(test_case.expected_result, tuple):
            attributes_to_analyze = test_case.expected_result
        else:
            attributes_to_analyze = (test_case.expected_result,)
        for resource_attribute in attributes_to_analyze:
            result = await test_case.resource.analyze(type(resource_attribute))
            assert result == resource_attribute

    async def test_run_analyzer(self, test_case: PopulatedAnalyzerTestCase):
        """
        Test that :func:`Resource.run` works on the given analyzer (REQ2.1).

        This test verifies that:
        - The resource can successfully run the analyzer via the run method
        - The expected attributes are properly set on the resource after running
        """
        await test_case.resource.run(test_case.analyzer_type)
        if isinstance(test_case.expected_result, tuple):
            expected_attributes = test_case.expected_result
        else:
            expected_attributes = (test_case.expected_result,)
        for resource_attribute in expected_attributes:
            result = test_case.resource.get_attributes(type(resource_attribute))
            assert result == resource_attribute

    async def test_no_valid_analyzer(self, test_case: PopulatedAnalyzerTestCase):
        """
        Test that running :func:`Resource.analyze` raises AnalyzerNotFoundError when no analyzer matches the given ResourceAttributes type (REQ2.1).

        This test verifies that:
        - The system properly raises an error when trying to analyze with a non-existent analyzer
        """
        with pytest.raises(NotFoundError):
            await test_case.resource.analyze(DummyAttributes)
