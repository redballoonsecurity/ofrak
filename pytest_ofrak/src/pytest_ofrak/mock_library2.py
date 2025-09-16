from pytest_ofrak.mock_component_types import MockAnalyzer
from pytest_ofrak.mock_library import (
    ITargetsRROutputsD,
    ITargetsPOutputsA,
)


class AlternativeTargetsRROutputsD(MockAnalyzer, ITargetsRROutputsD):
    pass


class AlternativeTargetsPOutputsA(MockAnalyzer, ITargetsPOutputsA):
    pass
