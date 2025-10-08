from ofrak.component.identifier import Identifier
from ofrak.core.program import Program
from ofrak.resource import Resource
from ofrak.resource_view import ResourceView


class BinaryNinjaAnalysisResource(ResourceView):
    pass


class BinaryNinjaAnalysisIdentifier(Identifier):
    """
    Tags Program resources for Binary Ninja analysis. Enables Binary Ninja-based components to run on the resource.
    Automatically identifies programs that should be analyzed with Binary Ninja.
    """

    id = b"BinaryNinjaAnalysisIdentifier"
    targets = (Program,)

    async def identify(self, resource: Resource, config=None):
        resource.add_tag(BinaryNinjaAnalysisResource)
