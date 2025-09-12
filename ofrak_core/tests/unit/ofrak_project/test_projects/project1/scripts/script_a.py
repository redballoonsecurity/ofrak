from ofrak import *
from ofrak.core import *
from ofrak.gui.script_builder import get_child_by_range  # noqa


async def main(ofrak_context: OFRAKContext, root_resource: Optional[Resource]):
    if root_resource is None:
        raise ValueError()

    await root_resource.unpack()
