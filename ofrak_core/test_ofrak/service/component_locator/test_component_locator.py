from dataclasses import dataclass
from typing import Type, Optional, Iterable, Tuple

import pytest

from ofrak.component.abstract import AbstractComponent
from ofrak.component.analyzer import Analyzer
from ofrak.component.interface import ComponentInterface
from ofrak.component.unpacker import Unpacker
from ofrak.service.component_locator import (
    ComponentLocator,
    InvalidComponentError,
)
from ofrak.service.component_locator_i import (
    ComponentLocatorInterface,
    ComponentFilter,
)
from ofrak.model.component_filters import (
    ComponentWhitelistFilter,
    ComponentTypeFilter,
    ComponentTargetFilter,
    AnalyzerOutputFilter,
    ComponentOrMetaFilter,
    ComponentAndMetaFilter,
    ComponentPrioritySelectingMetaFilter,
    ComponentNotMetaFilter,
)
from ofrak_type.error import NotFoundError
from pytest_ofrak.mock_component_types import MockAnalyzer
from pytest_ofrak import mock_library2, mock_library
from pytest_ofrak.mock_library import (
    TargetsCommonOutputsA,
    TargetsQOutputsABC,
    TargetsPOutputsA,
    AbstractionAttributesA,
    AbstractionP,
    AbstractionRR,
    AbstractionAttributesD,
    TargetsRROutputsD,
    AbstractionR,
    ITargetsRROutputsD,
    IWithoutImplementation,
    AbstractionAttributesUnknown,
    AbstractionPUnpacker,
    AbstractionCommon,
    AbstractionRUnpacker,
    AbstractionRRUnpacker,
    AbstractionAttributesB,
    AbstractionAttributesC,
)
from pytest_ofrak.mock_library2 import AlternativeTargetsRROutputsD


@pytest.fixture
def component_locator():
    return ComponentLocator()


@pytest.fixture
def analyzers_for_testing():
    return [
        TargetsPOutputsA(),
        TargetsCommonOutputsA(),
        TargetsQOutputsABC(),
        TargetsRROutputsD(),
    ]


@pytest.fixture
def unpackers_for_testing():
    return [
        AbstractionPUnpacker(),
        AbstractionRUnpacker(),
        AbstractionRRUnpacker(),
    ]


@pytest.fixture
def packers_for_testing():
    return []


@pytest.fixture
def identifiers_for_testing():
    return []


@pytest.fixture
def modifiers_for_testing():
    return []


@pytest.fixture
def components_for_testing(
    unpackers_for_testing,
    analyzers_for_testing,
    packers_for_testing,
    identifiers_for_testing,
    modifiers_for_testing,
):
    return (
        analyzers_for_testing
        + unpackers_for_testing
        + packers_for_testing
        + identifiers_for_testing
        + modifiers_for_testing
    )


def test_add_components(component_locator, components_for_testing):
    component_locator.add_components(components_for_testing)

    with pytest.raises(InvalidComponentError):
        # Duplicate components
        component_locator.add_components(components_for_testing)

    class UnclassifiedComponent(AbstractComponent):
        id = b"UnclassifiedComponent"
        targets = [AbstractionP]

        def __init__(self):
            super().__init__(None, None, None)  # type: ignore

        async def _run(self, resource, config=None):
            pass

        @classmethod
        def get_default_config(cls):
            return None

    with pytest.raises(InvalidComponentError):
        # Component that is not an Unpacker, Modifier, Analyzer, etc.
        component_locator.add_components([UnclassifiedComponent()])

    class AnalyzerWithNoTarget(MockAnalyzer):
        outputs = (AbstractionAttributesA,)

    with pytest.raises(TypeError):
        # Component does not define a target
        component_locator.add_components([AnalyzerWithNoTarget()])

    class AnalyzerWithNoOutputs(MockAnalyzer):
        targets = (AbstractionP,)

    with pytest.raises(TypeError):
        # Analyzer does not define outputs
        component_locator.add_components([AnalyzerWithNoOutputs()])


@pytest.fixture
def populated_component_locator(component_locator, components_for_testing):
    component_locator.add_components(components_for_testing)
    return component_locator


@dataclass
class GetByTypeTestCase:
    label: str
    component_interface: Type[ComponentInterface]
    expected_component_class: Optional[Type[ComponentInterface]]

    def run_test(self, locator: ComponentLocatorInterface):
        if self.expected_component_class is None:
            with pytest.raises(NotFoundError):
                _ = locator.get_by_type(self.component_interface)
        else:
            component = locator.get_by_type(self.component_interface)
            assert type(component) == self.expected_component_class


GET_BY_TYPE_TEST_CASES = [
    GetByTypeTestCase("analyzer with implementation", ITargetsRROutputsD, TargetsRROutputsD),
    GetByTypeTestCase("analyzer without implementation", IWithoutImplementation, None),
]


@pytest.mark.parametrize("test_case", GET_BY_TYPE_TEST_CASES, ids=lambda t: t.label)
def test_get_by_type(populated_component_locator, test_case: GetByTypeTestCase):
    test_case.run_test(populated_component_locator)


@dataclass
class GetComponentMatchingFiltersTestCase:
    label: str
    filters: Tuple[ComponentFilter, ...]
    expected_component_types: Iterable[Type[ComponentInterface]]

    def run_test(self, locator: ComponentLocatorInterface):
        component_filter = ComponentAndMetaFilter(*self.filters)
        if self.expected_component_types is None:
            with pytest.raises(NotFoundError):
                _ = locator.get_components_matching_filter(component_filter)
        else:
            components = locator.get_components_matching_filter(component_filter)
            component_types = {type(comp) for comp in components}
            for expected_component_type in self.expected_component_types:
                assert (
                    expected_component_type in component_types
                ), f"{expected_component_type.__name__} not located"
                component_types.remove(expected_component_type)
            assert 0 == len(component_types), (
                f"Got components {component_types} in addition to "
                f"expected types {self.expected_component_types}"
            )


GET_COMPONENTS_TEST_CASES = [
    GetComponentMatchingFiltersTestCase(
        "can whitelist specific components",
        (ComponentWhitelistFilter(TargetsQOutputsABC.get_id(), TargetsPOutputsA.get_id()),),
        (TargetsQOutputsABC, TargetsPOutputsA),
    ),
    GetComponentMatchingFiltersTestCase(
        "can blacklist specific components",
        (
            ComponentTypeFilter(Analyzer),
            ComponentNotMetaFilter(
                ComponentWhitelistFilter(TargetsQOutputsABC.get_id(), TargetsPOutputsA.get_id())
            ),
        ),
        (TargetsCommonOutputsA, TargetsRROutputsD),
    ),
    GetComponentMatchingFiltersTestCase(
        "can filter by type",
        (ComponentTypeFilter(Unpacker),),
        (
            AbstractionPUnpacker,
            AbstractionRUnpacker,
            AbstractionRRUnpacker,
        ),
    ),
    GetComponentMatchingFiltersTestCase(
        "exactly one analyzer targets RR and outputs D",
        (
            ComponentTypeFilter(Analyzer),
            AnalyzerOutputFilter(AbstractionAttributesD),
            ComponentPrioritySelectingMetaFilter(
                ComponentTargetFilter(AbstractionRR),
                ComponentTargetFilter(AbstractionR),
                ComponentTargetFilter(AbstractionCommon),
            ),
        ),
        (TargetsRROutputsD,),
    ),
    GetComponentMatchingFiltersTestCase(
        "one targets P, one targets super(P), choose analyzer targeting P",
        (
            ComponentTypeFilter(Analyzer),
            AnalyzerOutputFilter(AbstractionAttributesA),
            ComponentTargetFilter(AbstractionP),
        ),
        (TargetsPOutputsA,),
    ),
    GetComponentMatchingFiltersTestCase(
        "analyzer targets subclass of R, produces D",
        (
            ComponentTypeFilter(Analyzer),
            AnalyzerOutputFilter(AbstractionAttributesD),
            ComponentPrioritySelectingMetaFilter(
                ComponentTargetFilter(AbstractionRR),
                ComponentTargetFilter(AbstractionR),
                ComponentTargetFilter(AbstractionCommon),
            ),
        ),
        (TargetsRROutputsD,),
    ),
    GetComponentMatchingFiltersTestCase(
        "no analyzer producing attributes",
        (
            ComponentTypeFilter(Analyzer),
            AnalyzerOutputFilter(AbstractionAttributesUnknown),
        ),
        (),
    ),
    GetComponentMatchingFiltersTestCase(
        "most specific unpacker would be chosen",
        (
            ComponentTypeFilter(Unpacker),
            ComponentPrioritySelectingMetaFilter(
                ComponentTargetFilter(AbstractionRR),
                ComponentTargetFilter(AbstractionR),
            ),
        ),
        (AbstractionRRUnpacker,),
    ),
    GetComponentMatchingFiltersTestCase(
        "xor filter filters out all",
        (
            ComponentTypeFilter(Analyzer),
            AnalyzerOutputFilter(AbstractionAttributesA),
            AnalyzerOutputFilter(AbstractionAttributesB),
            AnalyzerOutputFilter(AbstractionAttributesC),
            ComponentPrioritySelectingMetaFilter(
                ComponentTargetFilter(AbstractionP),
            ),
        ),
        (),
    ),
    GetComponentMatchingFiltersTestCase(
        "analyzer output filter doesn't hard fail on non-analyzers",
        (
            ComponentTypeFilter(Unpacker),
            AnalyzerOutputFilter(AbstractionAttributesA),
        ),
        (),
    ),
    GetComponentMatchingFiltersTestCase(
        "multiple component types allowed",
        (
            ComponentOrMetaFilter(ComponentTypeFilter(Analyzer), ComponentTypeFilter(Unpacker)),
            ComponentTargetFilter(AbstractionP),
        ),
        (TargetsPOutputsA, AbstractionPUnpacker),
    ),
    GetComponentMatchingFiltersTestCase(
        "empty OR filter allows all components",
        (ComponentOrMetaFilter(),),
        (
            TargetsPOutputsA,
            TargetsCommonOutputsA,
            TargetsQOutputsABC,
            TargetsRROutputsD,
            AbstractionPUnpacker,
            AbstractionRUnpacker,
            AbstractionRRUnpacker,
        ),
    ),
    GetComponentMatchingFiltersTestCase(
        "match only the analyzer outputting ALL the requested attributes",
        (
            AnalyzerOutputFilter(
                AbstractionAttributesA, AbstractionAttributesB, AbstractionAttributesC
            ),
        ),
        (TargetsQOutputsABC,),
    ),
]


@pytest.mark.parametrize("test_case", GET_COMPONENTS_TEST_CASES, ids=lambda t: t.label)
def test_get_components_matching_filter(
    populated_component_locator, test_case: GetComponentMatchingFiltersTestCase
):
    test_case.run_test(populated_component_locator)


def test_no_module_priority(populated_component_locator):
    with pytest.raises(InvalidComponentError):
        populated_component_locator.add_components([AlternativeTargetsRROutputsD()])


def test_module_1_has_priority(populated_component_locator):
    populated_component_locator.add_components(
        [AlternativeTargetsRROutputsD()], [mock_library2, mock_library]
    )

    registed_component_with_id = populated_component_locator.get_by_id(ITargetsRROutputsD.get_id())
    assert type(registed_component_with_id) is TargetsRROutputsD


def test_module_2_has_priority(populated_component_locator):
    populated_component_locator.add_components(
        [AlternativeTargetsRROutputsD()], [mock_library, mock_library2]
    )

    registed_component_with_id = populated_component_locator.get_by_id(ITargetsRROutputsD.get_id())
    assert type(registed_component_with_id) is AlternativeTargetsRROutputsD
