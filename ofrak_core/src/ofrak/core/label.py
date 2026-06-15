from dataclasses import dataclass

from ofrak.model.resource_model import index

from ofrak.core.addressable import Addressable


@dataclass
class LabeledAddress(Addressable):
    name: str

    @index
    def Label(self) -> str:
        return self.name
