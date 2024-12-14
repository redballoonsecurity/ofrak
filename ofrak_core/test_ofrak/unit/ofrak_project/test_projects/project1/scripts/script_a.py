from ofrak import *
from ofrak.core import *


def main(ofrak_context: OFRAKContext, root_resource: Optional[Resource]):
    if root_resource is None:
        raise ValueError()

    root_resource.unpack()
