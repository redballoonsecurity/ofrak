from ofrak.core.filesystem import File
from ofrak_binary_ninja.model import BinaryNinjaAnalysis

from ofrak import OFRAKContext


async def test_binary_ninja_analyzer(hello_elf: bytes, ofrak_context: OFRAKContext, test_id: str):
    """
    Test that the [BinaryNinjaAnalysis][ofrak_binary_ninja.model.BinaryNinjaAnalysis]
    object can be successfully generated
    """
    resource = await ofrak_context.create_root_resource(test_id, hello_elf, tags=(File,))
    await resource.identify()
    analysis = resource.analyze(BinaryNinjaAnalysis)
    assert isinstance(analysis, BinaryNinjaAnalysis)
