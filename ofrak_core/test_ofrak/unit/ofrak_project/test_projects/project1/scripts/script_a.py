from ofrak import *
from ofrak.core import *


async def main(ofrak_context: OFRAKContext, root_resource: Optional[Resource]):
    if root_resource is None:
        raise ValueError()

    await root_resource.unpack()
