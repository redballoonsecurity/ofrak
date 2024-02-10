from ofrak_binary_ninja.components.binary_ninja_analyzer import BINJA_TOOL
from pytest_ofrak.patterns.data_refs_analyzer import DataRefsAnalyzerTestPattern


class TestBinjaDataRefsAnalyzer(DataRefsAnalyzerTestPattern):
    async def test_installed(self) -> None:
        assert await BINJA_TOOL.is_tool_installed()
