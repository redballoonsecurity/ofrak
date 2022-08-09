import hashlib
from dataclasses import dataclass

from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import File

from ofrak.component.analyzer import Analyzer
from ofrak.model.resource_model import ResourceAttributes
from ofrak.resource import Resource


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class Sha256Attributes(ResourceAttributes):
    checksum: str


class Sha256Analyzer(Analyzer[None, Sha256Attributes]):
    """
    Analyze binary data and add attributes with the SHA256 checksum of the data.
    """

    targets = (File, GenericBinary)
    outputs = (Sha256Attributes,)

    async def analyze(self, resource: Resource, config=None) -> Sha256Attributes:
        data = await resource.get_data()
        sha256 = hashlib.sha256()
        sha256.update(data)
        return Sha256Attributes(sha256.hexdigest())


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class Md5Attributes(ResourceAttributes):
    checksum: str


class Md5Analyzer(Analyzer[None, Md5Attributes]):
    """
    Analyze binary data and add attributes with the MD5 checksum of the data.
    """

    targets = (File, GenericBinary)
    outputs = (Md5Attributes,)

    async def analyze(self, resource: Resource, config=None) -> Md5Attributes:
        data = await resource.get_data()
        md5 = hashlib.md5()
        md5.update(data)
        return Md5Attributes(md5.hexdigest())
