
import os
from ofrak.ofrak_context import OFRAKContext
from ofrak_pyghidra.components.pyghidra_components import PyGhidraUnpacker

async def test_pyghidra_code_region_unpacker(ofrak_context: OFRAKContext):
    root_resource = await ofrak_context.create_root_resource_from_file(
        os.path.join(os.path.dirname(__file__), "assets/hello.x64.elf")
    )
    
    await root_resource.run(PyGhidraUnpacker)