from typing import List
import re
from ofrak_angr.model import AngrDecompilationAnalysis
from ofrak.ofrak_context import OFRAKContext

from ofrak.core.complex_block import ComplexBlock
from ofrak.service.resource_service_i import ResourceFilter



async def test_angr_decompilation(ofrak_context: OFRAKContext):
    root_resource = await ofrak_context.create_root_resource_from_file("assets/hello.x64.elf")
    await root_resource.unpack_recursively(do_not_unpack=[ComplexBlock,])
    complex_blocks: List[ComplexBlock] = await root_resource.get_descendants_as_view(ComplexBlock, r_filter=ResourceFilter(tags=[ComplexBlock,]))
    decomps = []
    for complex_block in complex_blocks:
        decomps.append(await complex_block.resource.analyze(AngrDecompilationAnalysis))
    assert len(decomps) == 11