from test_ofrak.service.component_locator.mock_library import (
    MockAnalyzer,
    ITargetsRROutputsD,
    ITargetsPOutputsA,
)


class AlternativeTargetsRROutputsD(MockAnalyzer, ITargetsRROutputsD):
    pass


class AlternativeTargetsPOutputsA(MockAnalyzer, ITargetsPOutputsA):
    pass
