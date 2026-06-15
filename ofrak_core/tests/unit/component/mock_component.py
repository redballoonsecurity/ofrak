from dataclasses import dataclass
from dataclasses import dataclass

from ofrak.component.unpacker import Unpacker
from ofrak.component.packer import Packer
from ofrak.core.binary import GenericBinary
from ofrak.model.component_model import ComponentConfig
from ofrak.resource import Resource


@dataclass
class MockUnpackerConfig(ComponentConfig):
    field_a: int
    field_b: int


class MockUnpackerRequiresDefault(Unpacker[MockUnpackerConfig]):
    """
    Component fails if the given config does not match a specific config value, which is the
    default.
    """

    targets = (GenericBinary,)
    children = ()

    async def unpack(
        self,
        resource: Resource,
        config: MockUnpackerConfig = MockUnpackerConfig(3, 6),
    ) -> None:
        assert config is not None

        assert config.field_a == 3
        assert config.field_b == 6


class MockUnpackerWithDefaultRequiresPopulated(Unpacker[MockUnpackerConfig]):
    """
    Component fails if the given config does not match a specific config value, which is not the
    default. The valid config must be successfully passed, and the default not used, for it to
    not fail.
    """

    targets = (GenericBinary,)
    children = ()

    async def unpack(
        self, resource: Resource, config: MockUnpackerConfig = MockUnpackerConfig(3, 6)
    ) -> None:
        assert config is not None

        assert config.field_a == 4
        assert config.field_b == 8


class MockUnpackerModifiesDefaultArgument(Unpacker[MockUnpackerConfig]):
    """
    Component modifies the config after checking its field. When run twice in a row,
    this would fail if the default config value is modifiable within the component body.
    """

    targets = (GenericBinary,)
    children = ()

    async def unpack(
        self, resource: Resource, config: MockUnpackerConfig = MockUnpackerConfig(3, 6)
    ) -> None:
        assert config is not None

        assert config.field_a == 3
        assert config.field_b == 6

        config.field_a = 1
        config.field_b = 2


@dataclass
class MockFile(GenericBinary):
    """
    Mock file type
    """


class MockFilePacker(Packer[None]):
    """
    Mock file type unpacker
    """

    id = b"MockFilePacker"
    targets = (MockFile,)

    async def pack(self, resource: Resource, config=None):
        print("packing...")
        print("done!")


@dataclass
class MockFailFile(GenericBinary):
    """
    Mock file type that should fail for packing because no packer is registered
    """


class MockFailException(Exception):
    """
    An exception for our mock packer to throw
    """


class MockFailFilePacker(Packer[None]):
    """
    Mock file type unpacker
    """

    id = b"MockFailFilePacker"
    targets = (MockFailFile,)

    async def pack(self, resource: Resource, config=None):
        raise MockFailException("Raising an exception to mock a failing packer")
