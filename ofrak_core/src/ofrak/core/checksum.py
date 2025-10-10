import hashlib
from dataclasses import dataclass

from ofrak.core.binary import GenericBinary

from ofrak.component.analyzer import Analyzer
from ofrak.model.resource_model import ResourceAttributes
from ofrak.resource import Resource


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class Sha256Attributes(ResourceAttributes):
    checksum: str


class Sha256Analyzer(Analyzer[None, Sha256Attributes]):
    """
    Calculates the SHA-256 (Secure Hash Algorithm 256-bit) cryptographic hash of binary data,
    producing a 256-bit fingerprint. Use for file identification with high security, integrity
    verification for security-critical applications, malware analysis and sample tracking, creating
    file signatures for threat intelligence, or compliance scenarios requiring secure hashing.
    """

    targets = (GenericBinary,)
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
    Calculates the MD5 (Message Digest 5) cryptographic hash of binary data, producing a 128-bit
    fingerprint. Use for file identification by comparing against known MD5 databases, quick
    integrity verification to detect modifications, tracking changes during binary modification
    workflows, or creating file catalogs.
    """

    targets = (GenericBinary,)
    outputs = (Md5Attributes,)

    async def analyze(self, resource: Resource, config=None) -> Md5Attributes:
        data = await resource.get_data()
        md5 = hashlib.md5()
        md5.update(data)
        return Md5Attributes(md5.hexdigest())
