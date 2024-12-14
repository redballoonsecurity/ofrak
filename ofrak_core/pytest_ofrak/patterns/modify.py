from abc import ABC, abstractmethod

from ofrak import OFRAKContext
from ofrak.resource import Resource


class ModifyPattern(ABC):
    """
    Generic test pattern for modification. The test expects to:
    1. Create an initial root resource
    2. Modify the initial root resource
    3. Verify that the root resource matches some expected pattern

    Each step is broken out into an abstractmethod which subclasses of this pattern should
    implement.
    """

    def test_modify(self, ofrak_context):
        root_resource = self.create_root_resource(ofrak_context)
        self.modify(root_resource)
        self.verify(root_resource)

    @abstractmethod
    def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        """
        Create and return the root resource which will be unpacked
        """
        raise NotImplementedError()

    @abstractmethod
    def modify(self, root_resource: Resource) -> None:
        """
        Modify the root resource
        """
        raise NotImplementedError()

    @abstractmethod
    def verify(self, root_resource: Resource) -> None:
        """
        Verify that the root resource matches what is expected after repacking with the
        modifications
        """
        raise NotImplementedError()
