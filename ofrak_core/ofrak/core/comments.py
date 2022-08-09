from copy import deepcopy
from dataclasses import dataclass
from typing import Dict, Tuple, Optional

from ofrak.component.modifier import Modifier
from ofrak.model.component_model import ComponentConfig
from ofrak.model.resource_model import ResourceAttributes
from ofrak.resource import Resource
from ofrak_type.error import NotFoundError
from ofrak_type.range import Range


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class CommentsAttributes(ResourceAttributes):
    """
    User-defined comments, each comment associated with an optional range.
    """

    comments: Dict[Optional[Range], str]


@dataclass
class AddCommentModifierConfig(ComponentConfig):
    comment: Tuple[Optional[Range], str]


class AddCommentModifier(Modifier[AddCommentModifierConfig]):
    """
    Modifier to add a single comment to a resource.
    """

    targets = ()

    async def modify(self, resource: Resource, config: AddCommentModifierConfig) -> None:
        # Verify that the given range is valid for the given resource.
        config_range = config.comment[0]
        if config_range is not None:
            if config_range.start < 0 or config_range.end > len(await resource.get_data()):
                raise ValueError(
                    f"Range {config_range} is outside the bounds of "
                    f"resource {resource.get_id().hex()}"
                )

        try:
            # deepcopy the existing comments, otherwise they would be modified in place
            # and OFRAK would then compare the new attributes with the existing ones and find
            # they are the same, and report that the resource wasn't modified.
            comments = deepcopy(resource.get_attributes(CommentsAttributes).comments)
        except NotFoundError:
            comments = {}
        comments[config.comment[0]] = config.comment[1]
        resource.add_attributes(CommentsAttributes(comments=comments))


@dataclass
class DeleteCommentModifierConfig(ComponentConfig):
    comment_range: Optional[Range]


class DeleteCommentModifier(Modifier[DeleteCommentModifierConfig]):
    """
    Modifier to delete a comment from a resource.
    """

    targets = ()

    async def modify(self, resource: Resource, config: DeleteCommentModifierConfig) -> None:
        """
        Delete the comment associated with the given range.

        :raises NotFoundError: if the comment range is not associated with a comment.
        """
        try:
            comments = deepcopy(resource.get_attributes(CommentsAttributes).comments)
        except NotFoundError:
            comments = {}
        try:
            del comments[config.comment_range]
        except KeyError:
            raise NotFoundError(
                f"Comment range {config.comment_range} not found in "
                f"resource {resource.get_id().hex()}"
            )
        resource.add_attributes(CommentsAttributes(comments=comments))
