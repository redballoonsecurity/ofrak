from ofrak.component.identifier import Identifier
from ofrak.core import Elf, Ihex, Pe
from ofrak.core.program import Program
from ofrak.resource import Resource
from ofrak_ghidra.ghidra_model import GhidraAutoLoadProject, GhidraCustomLoadProject


_GHIDRA_AUTO_LOADABLE_FORMATS = [Elf, Ihex, Pe]


class GhidraAnalysisIdentifier(Identifier):
    """
    Component to identify resources to analyze with Ghidra. If this component is discovered,
    it will tag all [Program][ofrak.core.program.Program]s as GhidraProjects
    """

    id = b"GhidraAnalysisIdentifier"
    targets = (Program,)

    async def identify(self, resource: Resource, config=None):
        for tag in _GHIDRA_AUTO_LOADABLE_FORMATS:
            if resource.has_tag(tag):
                resource.add_tag(GhidraAutoLoadProject)
                return

        resource.add_tag(GhidraCustomLoadProject)
