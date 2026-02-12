from ofrak.component.identifier import Identifier
from ofrak.core import Elf, Ihex, Pe
from ofrak.core.program import Program
from ofrak.resource import Resource
from ofrak.resource_view import ResourceView


class BinaryNinjaAnalysisResource(ResourceView):
    pass


class BinaryNinjaAutoLoadProject(BinaryNinjaAnalysisResource):
    pass


class BinaryNinjaCustomLoadProject(BinaryNinjaAnalysisResource):
    pass


_BINARY_NINJA_AUTO_LOADABLE_FORMATS = [Elf, Ihex, Pe]


class BinaryNinjaAnalysisIdentifier(Identifier):
    """
    Tags Program resources for Binary Ninja analysis. Auto-loadable formats (ELF, PE, Ihex) get
    BinaryNinjaAutoLoadProject tag, others get BinaryNinjaCustomLoadProject. Enables Binary
    Ninja-based components to run on the resource.
    """

    id = b"BinaryNinjaAnalysisIdentifier"
    targets = (Program,)

    async def identify(self, resource: Resource, config=None):
        for tag in _BINARY_NINJA_AUTO_LOADABLE_FORMATS:
            if resource.has_tag(tag):
                resource.add_tag(BinaryNinjaAutoLoadProject)
                return

        resource.add_tag(BinaryNinjaCustomLoadProject)
