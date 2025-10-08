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
class BinaryExtendConfig(ComponentConfig):
    """
    Config for the [BinaryExtendModifier][ofrak.core.binary.BinaryExtendModifier].

    :ivar content: the extended bytes.
    """

    content: bytes


class BinaryExtendModifier(Modifier[BinaryExtendConfig]):
    """
    Appends arbitrary data to the end of a binary file, extending its size without modifying existing content. The extension can contain code, data, or padding as needed. Use for adding trailing data, creating space for signatures or metadata, appending code caves, adding debug information, or reserving space for future modifications. Simple but effective way to add content when modifying internal structures is too risky or complex.
    """

    targets = ()

    async def modify(self, resource: Resource, config: BinaryExtendConfig):
        if len(config.content) == 0:
            raise ValueError("Content of the extended space not provided")
        data = await resource.get_data()
        data += config.content
        resource.queue_patch(Range(0, await resource.get_data_length()), data)


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
    Replaces bytes at a specific file offset with provided patch bytes, performing direct binary patching without structural awareness. The patch must fit within existing boundaries or risk overwriting adjacent data. Use for targeted binary patches, fixing specific bugs, NOP-ing instructions, modifying constants or strings, applying binary diffs, or making surgical changes to specific locations. Most direct patching method but requires careful offset calculation and size management.
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
