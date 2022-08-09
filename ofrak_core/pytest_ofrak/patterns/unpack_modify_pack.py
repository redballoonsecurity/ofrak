from abc import ABC, abstractmethod
from difflib import ndiff

from ofrak import OFRAKContext
from ofrak.resource import Resource


class UnpackModifyPackPattern(ABC):
    """
    Generic test pattern for unpacker/packer pairing. The test expects to:
    1. Create an initial root resource
    2. Unpack that root resource
    3. Get one of the newly-created descendants of the root resource and modify that descendant
    4. Repack the root resource - because of the modification in step 4, the root resource should
    now have different data after this step.
    5. Verify that the repacked root resource matches some expected pattern

    Each step is broken out into an abstractmethod which subclasses of this pattern should
    implement.
    """

    async def test_unpack_modify_pack(self, ofrak_context):
        root_resource = await self.create_root_resource(ofrak_context)
        await self.unpack(root_resource)
        original_tree = await root_resource.summarize_tree()
        await self.modify(root_resource)
        modified_tree = await root_resource.summarize_tree()
        print("\n")
        print(
            "".join(
                ndiff(
                    original_tree.splitlines(keepends=True), modified_tree.splitlines(keepends=True)
                )
            ),
            end="",
        )
        await self.repack(root_resource)
        await self.verify(root_resource)

    @abstractmethod
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        """
        Create and return the root resource which will be unpacked
        """
        raise NotImplementedError()

    @abstractmethod
    async def unpack(self, root_resource: Resource) -> None:
        """
        Unpack the root resource
        """
        raise NotImplementedError()

    @abstractmethod
    async def modify(self, unpacked_root_resource: Resource) -> None:
        """
        Once the root resource is unpacked, the test needs to modify at least one of its
        descendants. This method should contain the logic to get those resource(s).
        """
        raise NotImplementedError()

    @abstractmethod
    async def repack(self, modified_root_resource: Resource) -> None:
        """
        Pack the root resource after it has been modified
        """
        raise NotImplementedError()

    @abstractmethod
    async def verify(self, repacked_root_resource: Resource) -> None:
        """
        Verify that the repacked root resource matches what is expected after repacking with the
        modifications
        """
        raise NotImplementedError()


class UnpackPackPattern(UnpackModifyPackPattern, ABC):
    async def modify(self, unpacked_root_resource: Resource) -> None:
        pass
