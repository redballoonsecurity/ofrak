from ofrak.component.identifier import Identifier
from ofrak.core import Elf, Ihex, Pe
from ofrak.core.program import Program
from ofrak.resource import Resource
from ofrak_ghidra.ghidra_model import GhidraAutoLoadProject, GhidraCustomLoadProject


_GHIDRA_AUTO_LOADABLE_FORMATS = [Elf, Ihex, Pe]


class GhidraAnalysisIdentifier(Identifier):
    """
    Tags Program resources for Ghidra analysis. Auto-loadable formats (ELF, PE, Ihex) get GhidraAutoLoadProject tag,
    others get GhidraCustomLoadProject. Enables Ghidra-based components to run on the resource.
    """

    id = b"GhidraAnalysisIdentifier"
    targets = (Program,)

    async def identify(self, resource: Resource, config=None):
        for tag in _GHIDRA_AUTO_LOADABLE_FORMATS:
            if resource.has_tag(tag):
                resource.add_tag(GhidraAutoLoadProject)
                return

        resource.add_tag(GhidraCustomLoadProject)
