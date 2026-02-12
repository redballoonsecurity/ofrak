from ofrak.component.identifier import Identifier
from ofrak.core import Elf, Ihex, Pe
from ofrak.core.program import Program
from ofrak.resource import Resource
from ofrak_angr.model import AngrAutoLoadProject, AngrCustomLoadProject


_ANGR_AUTO_LOADABLE_FORMATS = [Elf, Ihex, Pe]


class AngrAnalysisIdentifier(Identifier):
    """
    Tags Program resources for angr analysis. Auto-loadable formats (ELF, PE, Ihex) get
    AngrAutoLoadProject tag, others get AngrCustomLoadProject. Enables angr-based components
    to run on the resource.
    """

    id = b"AngrAnalysisIdentifier"
    targets = (Program,)

    async def identify(self, resource: Resource, config=None):
        for tag in _ANGR_AUTO_LOADABLE_FORMATS:
            if resource.has_tag(tag):
                resource.add_tag(AngrAutoLoadProject)
                return

        resource.add_tag(AngrCustomLoadProject)
