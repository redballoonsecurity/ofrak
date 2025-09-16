import logging
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, Union

from ofrak.component.abstract import ComponentMissingDependencyError
from ofrak_type import Range

try:
    import magic

    MAGIC_INSTALLED = True
except ImportError:
    MAGIC_INSTALLED = False

from ofrak.component.analyzer import Analyzer
from ofrak.component.identifier import Identifier
from ofrak.core.binary import GenericBinary, GenericText
from ofrak.model.component_model import ComponentExternalTool
from ofrak.model.resource_model import ResourceAttributes
from ofrak.model.tag_model import ResourceTag
from ofrak.resource import Resource
from ofrak_type.error import AlreadyExistError

LOGGER = logging.getLogger(__name__)


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class Magic(ResourceAttributes):
    mime: str
    descriptor: str


class _LibmagicDependency(ComponentExternalTool):
    def __init__(self):
        super().__init__(
            "libmagic",
            "https://www.darwinsys.com/file/",
            install_check_arg="",
            apt_package="libmagic1",
            brew_package="libmagic",
        )

        try:
            import magic as _magic

            _LibmagicDependency._magic = _magic
        except ImportError:
            _LibmagicDependency._magic = None

    async def is_tool_installed(self) -> bool:
        return MAGIC_INSTALLED


LIBMAGIC_DEP = _LibmagicDependency()


class MagicAnalyzer(Analyzer[None, Magic]):
    """
    Analyze a binary blob to extract its mimetype and magic description.
    """

    targets = (GenericBinary,)
    outputs = (Magic,)
    external_dependencies = (LIBMAGIC_DEP,)

    async def analyze(self, resource: Resource, config=None) -> Magic:
        data = await resource.get_data()
        if not MAGIC_INSTALLED:
            raise ComponentMissingDependencyError(self, LIBMAGIC_DEP)
        else:
            magic_mime = magic.from_buffer(data, mime=True)
            magic_description = magic.from_buffer(data)
            return Magic(magic_mime, magic_description)


class MagicIdentifier(Identifier[None]):
    """
    Identify resources using three identifier patterns:

    1. [MagicMimePattern][ofrak.core.magic.MagicMimePattern]
    2. [MagicDescriptionPattern][ofrak.core.magic.MagicDescriptionPattern]
    3. [RawMagicPattern][ofrak.core.magic.RawMagicPattern]

    OFRAK component authors can "register" magic patterns to run whenever this
    identifier is:

    ```python
    MagicMimePattern.register(GenericBinary, "application/octet-stream")
    ```
    """

    targets = (GenericBinary,)
    external_dependencies = (LIBMAGIC_DEP,)

    async def identify(self, resource: Resource, config=None) -> None:
        _magic = await resource.analyze(Magic)
        MagicMimePattern.run(resource, _magic.mime)
        MagicDescriptionPattern.run(resource, _magic.descriptor)
        await RawMagicPattern.run(resource)


class MagicMimePattern:
    """
    Pattern to tag resources based on their mimetype.
    """

    tags_by_mime: Dict[str, ResourceTag] = dict()

    @classmethod
    def register(cls, resource_tag: ResourceTag, mime_types: Union[Iterable[str], str]):
        """
        Register what resource tags correspond to specific mime types.
        """

        if isinstance(mime_types, str):
            mime_types = [mime_types]
        for mime_type in mime_types:
            if mime_type in cls.tags_by_mime:
                raise AlreadyExistError(f"Registering already-registered mime type: {mime_type}")
            cls.tags_by_mime[mime_type] = resource_tag

    @classmethod
    def run(cls, resource: Resource, magic_mime: str):
        """
        Run the pattern against a given resource, tagging it based on matching mime types.

        This method is designed to be called by the [MagicIdentifier][ofrak.core.magic.MagicIdentifier].
        """
        tag = cls.tags_by_mime.get(magic_mime)
        if tag is not None:
            resource.add_tag(tag)


class MagicDescriptionPattern:
    """
    Pattern to tag resources based on its mime description.
    """

    matchers: Dict[Callable, ResourceTag] = dict()

    @classmethod
    def register(cls, resource_tag: ResourceTag, matcher: Callable[[str], bool]):
        """
        Register a callable that determines whether the given resource tag should be applied.
        """
        if matcher in cls.matchers:
            raise AlreadyExistError("Registering already-registered matcher")
        cls.matchers[matcher] = resource_tag

    @classmethod
    def run(cls, resource: Resource, magic_description: str):
        """
        Run this pattern against a given resource, tagging it based on registered tags.

        This method is designed to be called by the [MagicIdentifier][ofrak.core.magic.MagicIdentifier].
        """
        for matcher, resource_type in cls.matchers.items():
            if matcher(magic_description):
                resource.add_tag(resource_type)


class RawMagicPattern:
    """
    Pattern to tag resource based on custom raw magic matching patterns.

    MAX_SEARCH_SIZE specifies how many bytes this pattern's `run` method exposes to registered
    matches (the first MAX_SEARCH_SIZE bytes of a resource are exposed).
    """

    matchers: Dict[Callable, ResourceTag] = dict()
    MAX_SEARCH_SIZE = 64

    @classmethod
    def register(cls, resource_tag: ResourceTag, matcher: Callable[[bytes], bool]):
        """
        Register a callable that determines whether the given resource tag should be applied.
        """
        if matcher in cls.matchers:
            raise AlreadyExistError("Registering already-registered matcher")
        cls.matchers[matcher] = resource_tag

    @classmethod
    async def run(cls, resource: Resource):
        """
        Run the pattern against a given resource, tagging it based on registered tags.
        Note that the first MAX_SEARCH_SIZE bytes of a resource are made available to the callable.

        This method is designed to be called by the [MagicIdentifier][ofrak.core.magic.MagicIdentifier].
        """
        data_length = min(await resource.get_data_length(), cls.MAX_SEARCH_SIZE)
        data = await resource.get_data(range=Range(0, data_length))
        for matcher, resource_type in cls.matchers.items():
            if matcher(data):
                resource.add_tag(resource_type)


MagicMimePattern.register(GenericText, "text/plain")
MagicDescriptionPattern.register(
    GenericText, lambda desc: any([("ASCII text" in s) for s in desc.split(", ")])
)

MagicMimePattern.register(GenericBinary, "application/octet-stream")
MagicDescriptionPattern.register(GenericBinary, lambda s: s == "data")
