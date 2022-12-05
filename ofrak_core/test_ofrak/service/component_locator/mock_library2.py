from pytest_ofrak.mock_component_types import MockAnalyzer
from test_ofrak.service.component_locator.mock_library import (
    ITargetsRROutputsD,
    ITargetsPOutputsA,
)


class AlternativeTargetsRROutputsD(MockAnalyzer, ITargetsRROutputsD):
    pass


class AlternativeTargetsPOutputsA(MockAnalyzer, ITargetsPOutputsA):
    pass
