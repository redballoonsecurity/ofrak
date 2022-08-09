from ofrak.component.identifier import Identifier
from ofrak.core.program import Program
from ofrak_binary_ninja.model import BinaryNinjaAnalysis
from ofrak.resource import Resource
from ofrak.resource_view import ResourceView


class BinaryNinjaAnalysisResource(ResourceView):
    async def get_binaryninja_analysis(self) -> BinaryNinjaAnalysis:
        return await self.resource.analyze(BinaryNinjaAnalysis)


class BinaryNinjaAnalysisIdentifier(Identifier):
    id = b"BinaryNinjaAnalysisIdentifier"
    targets = (Program,)

    async def identify(self, resource: Resource, config=None):
        resource.add_tag(BinaryNinjaAnalysisResource)
