from ofrak.component.identifier import Identifier
from ofrak.core.program import Program
from ofrak.resource import Resource
from ofrak_angr.model import AngrAnalysisResource


__all__ = ["AngrAnalysisIdentifier"]


class AngrAnalysisIdentifier(Identifier):
    id = b"AngrAnalysisIdentifier"
    targets = (Program,)

    async def identify(self, resource: Resource, config=None):
        resource.add_tag(AngrAnalysisResource)
