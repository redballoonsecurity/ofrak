from typing import List
import os
from ofrak.core.decompilation import DecompilationAnalysis, DecompilationAnalyzer
from ofrak.ofrak_context import OFRAKContext
from ofrak.core.complex_block import ComplexBlock
from ofrak.service.resource_service_i import ResourceFilter


async def test_ghidra_decompilation(ofrak_context: OFRAKContext):
    root_resource = await ofrak_context.create_root_resource_from_file(
        os.path.join(os.path.dirname(__file__), "assets/hello.x64.elf")
    )
    await root_resource.unpack_recursively(
        do_not_unpack=[
            ComplexBlock,
        ]
    )
    complex_blocks: List[ComplexBlock] = await root_resource.get_descendants_as_view(
        ComplexBlock,
        r_filter=ResourceFilter(
            tags=[
                ComplexBlock,
            ]
        ),
    )
    decomps = []
    for complex_block in complex_blocks:
        await complex_block.resource.run(DecompilationAnalyzer)
        ghidra_resource: DecompilationAnalysis = await complex_block.resource.view_as(
            DecompilationAnalysis
        )
        decomps.append(ghidra_resource.decompilation)
    assert len(decomps) == 14
    assert "" not in decomps
    assert "main" in " ".join(decomps)
    assert "print" in " ".join(decomps)
