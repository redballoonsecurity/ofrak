from dataclasses import dataclass

from ofrak.resource import Resource

from ofrak.resource_view import ResourceView
from ofrak_type.range import Range
from ofrak.component.modifier import Modifier, ModifierError
from ofrak.model.component_model import ComponentConfig


class GenericBinary(ResourceView):
    """
    A generic binary blob.
    """


class GenericText(GenericBinary):
    """
    A binary that consists of lines of text.
    """


@dataclass
class BinaryPatchConfig(ComponentConfig):
    """
    Config for the [BinaryPatchModifier][ofrak.core.binary.BinaryPatchModifier].

    :ivar offset: physical offset from beginning of resource where the patch should be applied
    :ivar patch_bytes: the raw bytes to patch
    """

    offset: int
    patch_bytes: bytes

    def get_range(self):
        return Range.from_size(self.offset, len(self.patch_bytes))


class BinaryPatchModifier(Modifier[BinaryPatchConfig]):
    """
    Patch a binary at the target offset with the given patch bytes.
    """

    targets = ()

    async def modify(self, resource: Resource, config: BinaryPatchConfig) -> None:
        """
        Patch the resource at the target offset with the given patch bytes.

        :param resource: the resource to patch
        :param config: contains the offset at which to patch and the patch bytes to apply

        :raises ModifierError: if the binary patch overflows the original size of the resource
        """
        resource_size = await resource.get_data_length()
        if len(config.patch_bytes) > resource_size - config.offset:
            raise ModifierError(
                f"The binary patch, {config}, overflows the original size of the resource "
                f"{resource.get_id().hex()}."
            )
        resource.queue_patch(config.get_range(), config.patch_bytes)
        return
