import os.path

from ofrak import Modifier, Resource
from ofrak_ghidra.ghidra_model import OfrakGhidraScript, OfrakGhidraMixin


class GhidraExampleComponent(Modifier, OfrakGhidraMixin):
    get_code_regions_script = OfrakGhidraScript(
        os.path.join(os.path.dirname(__file__), "ghidra_scripts", "GetCodeRegionsDuplicate.java"),
    )
    targets = ()

    async def modify(self, resource: Resource, config=None) -> None:
        _ = await self.get_code_regions_script.call_script(resource)
