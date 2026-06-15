from ofrak.component.identifier import Identifier
from ofrak.core.program import Program
from ofrak.resource import Resource
from ofrak_angr.model import AngrAnalysisResource


class AngrAnalysisIdentifier(Identifier):
    """
    Tags Program resources for angr analysis. Enables angr-based components to run on the resource. Automatically
    identifies programs that should be analyzed with angr.
    """

    id = b"AngrAnalysisIdentifier"
    targets = (Program,)

    async def identify(self, resource: Resource, config=None):
        resource.add_tag(AngrAnalysisResource)
