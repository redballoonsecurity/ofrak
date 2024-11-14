from copy import deepcopy
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional
from ofrak.component.modifier import Modifier
from ofrak.model.component_model import ComponentConfig
from ofrak.model.resource_model import ResourceAttributes
from ofrak.resource import Resource
from ofrak_type.error import NotFoundError
from ofrak_type.range import Range


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class CommentsAttributes(ResourceAttributes):
    """
    User-defined comments, list of the comments associated with an optional range.
    """

    comments: Dict[Optional[Range], List[str]]


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

        if config.comment[0] not in comments:
            comments[config.comment[0]] = []

        comments[config.comment[0]].append(config.comment[1])
        resource.add_attributes(CommentsAttributes(comments=comments))


@dataclass
class DeleteCommentModifierConfig(ComponentConfig):
    """
    If comment_text is provided, deletes the matching comment in that comment_range
    If comment_text is None, deletes ALL comments in that comment_range
    """

    comment_range: Optional[Range]
    comment_text: Optional[str] = None


class DeleteCommentModifier(Modifier[DeleteCommentModifierConfig]):
    """
    Modifier to delete comment(s) from a resource.
    """

    targets = ()

    async def modify(self, resource: Resource, config: DeleteCommentModifierConfig) -> None:
        """
        Delete the comment(s) associated with the given range.

        :raises NotFoundError: if the comment range is not associated with a comment.
        """
        try:
            comments = deepcopy(resource.get_attributes(CommentsAttributes).comments)
        except NotFoundError:
            comments = {}
        try:
            if config.comment_text is None:
                # Delete ALL comments in this range
                del comments[config.comment_range]
            else:
                comments[config.comment_range].remove(config.comment_text)
                # Clean up if this was the last comment in this range
                if len(comments[config.comment_range]) == 0:
                    del comments[config.comment_range]
        except KeyError:
            raise NotFoundError(
                f"Comment range {config.comment_range} not found in "
                f"resource {resource.get_id().hex()}"
            )
        except ValueError:
            raise NotFoundError(
                f"Comment {config.comment_text} with range {config.comment_range}"
                f" not found in resource {resource.get_id().hex()}"
            )
        resource.add_attributes(CommentsAttributes(comments=comments))
