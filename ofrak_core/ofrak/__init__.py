from ofrak.component.analyzer import Analyzer as Analyzer
from ofrak.component.identifier import Identifier as Identifier
from ofrak.component.modifier import Modifier as Modifier
from ofrak.component.packer import Packer as Packer
from ofrak.component.unpacker import Unpacker as Unpacker
from ofrak.model.resource_model import (
    ResourceAttributes as ResourceAttributes,
    ResourceModel as ResourceModel,
    Data as Data,
)
from ofrak.model.tag_model import ResourceTag as ResourceTag
from ofrak.ofrak_context import OFRAK as OFRAK, OFRAKContext as OFRAKContext
from ofrak.resource import Resource as Resource, ResourceFactory as ResourceFactory
from ofrak.service.resource_service_i import (
    ResourceFilter as ResourceFilter,
    ResourceAttributeValueFilter as ResourceAttributeValueFilter,
    ResourceAttributeRangeFilter as ResourceAttributeRangeFilter,
    ResourceAttributeFilter as ResourceAttributeFilter,
    ResourceAttributeValuesFilter as ResourceAttributeValuesFilter,
    ResourceFilterCondition as ResourceFilterCondition,
    ResourceSort as ResourceSort,
)

# Many existing OFRAK scripts rely on Optional being star-imported for the
# function signature
#     async def main(ofrak_context: OFRAKContext, root_resource: Optional[Resource] = None):
from typing import Optional as Optional
