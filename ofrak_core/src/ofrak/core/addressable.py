from dataclasses import dataclass


from ofrak.model.resource_model import index
from ofrak.resource_view import ResourceView


@dataclass
class Addressable(ResourceView):
    """
    A resource with a virtual address.

    :ivar virtual_address: the virtual address
    """

    virtual_address: int

    @index
    def VirtualAddress(self) -> int:
        return self.virtual_address
