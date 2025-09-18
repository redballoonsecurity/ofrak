from datetime import timedelta
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis.strategies import text
from ofrak.resource import Resource

from ofrak.core.comments import (
    AddCommentModifierConfig,
    AddCommentModifier,
    CommentsAttributes,
    DeleteCommentModifierConfig,
    DeleteCommentModifier,
)
from ofrak.core.magic import Magic
from ofrak_type.error import NotFoundError
from ofrak_type.range import Range


@pytest.fixture
async def executable_resource(ofrak_context, elf_executable_file) -> Resource:
    root_resource = await ofrak_context.create_root_resource_from_file(elf_executable_file)
    return root_resource


def get_comment_count(comment_attributes: CommentsAttributes) -> int:
    return sum(len(comment_list) for comment_list in comment_attributes.comments.values())


async def test_adding_comments(executable_resource: Resource):
    """Test adding comments, including to the entire resource (range=None)."""
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(Range(0, 1), "comment")),
    )
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(None, "comment")),
    )
    comment_attributes = executable_resource.get_attributes(CommentsAttributes)
    assert get_comment_count(comment_attributes) == 2


async def test_adding_comments_same_range(executable_resource: Resource):
    """Test adding multiple comments to the same range, including duplicated messages"""
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(Range(0, 1), "range 1 first comment")),
    )
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(Range(0, 1), "range 1 second comment")),
    )
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(None, "full range first comment")),
    )
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(None, "full range second comment")),
    )
    # Test duplicate comments (same range, same message)
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(Range(0, 1), "range 1 second comment")),
    )
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(None, "full range second comment")),
    )
    comment_attributes = executable_resource.get_attributes(CommentsAttributes)
    assert get_comment_count(comment_attributes) == 6


# We suppress the function_scoped_fixture health check because the executable_resource fixture
# doesn't need to be reset between individual runs of hypothesis (since the comment overrides
# the previous one every time).
@settings(
    deadline=timedelta(seconds=5),
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(comment_str=text())
async def test_comment_content(executable_resource: Resource, comment_str: str):
    """Test comments with all kinds of string contents."""
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(None, comment_str)),
    )
    comments = executable_resource.get_attributes(CommentsAttributes).comments
    assert comments[None] == [comment_str]
    await executable_resource.run(
        DeleteCommentModifier,
        DeleteCommentModifierConfig(comment_range=(None)),
    )
    comment_attributes = executable_resource.get_attributes(CommentsAttributes)
    assert get_comment_count(comment_attributes) == 0


async def test_range_validation(executable_resource: Resource):
    """Test that adding comments to out-of-bounds ranges raises an error."""
    data_len = len(await executable_resource.get_data())
    for r in [Range(0, data_len + 1), Range(data_len + 1, data_len + 2)]:
        with pytest.raises(ValueError):
            await executable_resource.run(
                AddCommentModifier,
                AddCommentModifierConfig(comment=(r, "comment")),
            )


@pytest.mark.parametrize("recursively", [True, False])
async def test_comments_survive_unpacking(executable_resource: Resource, recursively: bool):
    """Test that unpacking a resource after adding comments does not lose the comments."""
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(Range(0, 1), "comment")),
    )
    # Unpack the resource
    if recursively:
        component_run_result = await executable_resource.unpack_recursively()
    else:
        component_run_result = await executable_resource.unpack()
    assert len(component_run_result.resources_created) > 0
    comment_attributes = executable_resource.get_attributes(CommentsAttributes)
    assert get_comment_count(comment_attributes) == 1


@pytest.mark.parametrize("recursively", [True, False])
async def test_comments_survive_repacking(executable_resource: Resource, recursively: bool):
    """Test that repacking a resource after adding comments does not lose the comments."""
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(Range(0, 1), "comment")),
    )
    # Unpack and repack the resource
    if recursively:
        await executable_resource.unpack_recursively()
        await executable_resource.pack_recursively()
    else:
        await executable_resource.unpack()
        await executable_resource.pack()
    comment_attributes = executable_resource.get_attributes(CommentsAttributes)
    assert get_comment_count(comment_attributes) == 1


async def test_comments_survive_analyzing(executable_resource: Resource):
    """Test that analyzing a resource after adding comments does not lose the comments."""
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(Range(0, 1), "comment")),
    )
    # Analyze the resource
    await executable_resource.analyze(Magic)
    comment_attributes = executable_resource.get_attributes(CommentsAttributes)
    assert get_comment_count(comment_attributes) == 1


async def test_deleting_comments(executable_resource: Resource):
    """Test deleting comments."""
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(Range(0, 1), "first range comment 1")),
    )
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(Range(0, 1), "first range comment 2")),
    )
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(Range(0, 2), "second range comment 1")),
    )
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(Range(0, 2), "second range comment 2")),
    )
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(Range(1, 2), "third range comment 1")),
    )
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(Range(1, 2), "third range comment 2")),
    )
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(None, "full range comment 1")),
    )
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(None, "full range comment 2")),
    )
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(None, "full range comment 3")),
    )
    comment_attributes = executable_resource.get_attributes(CommentsAttributes)
    assert get_comment_count(comment_attributes) == 9
    # Test deletion of specific comments
    await executable_resource.run(
        DeleteCommentModifier,
        DeleteCommentModifierConfig(
            comment_range=Range(0, 1), comment_text="first range comment 1"
        ),
    )
    comment_attributes = executable_resource.get_attributes(CommentsAttributes)
    comments = comment_attributes.comments
    assert get_comment_count(comment_attributes) == 8
    assert len(comments[Range(0, 1)]) == 1
    assert comments[Range(0, 1)][0] == "first range comment 2"
    # Test specific deletion of last comment in a range
    await executable_resource.run(
        DeleteCommentModifier,
        DeleteCommentModifierConfig(
            comment_range=Range(0, 1), comment_text="first range comment 2"
        ),
    )
    comment_attributes = executable_resource.get_attributes(CommentsAttributes)
    comments = comment_attributes.comments
    assert get_comment_count(comment_attributes) == 7
    with pytest.raises(KeyError):
        # This key shouldn't exist anymore
        assert len(comments[Range(0, 1)]) == 0
    # Test deletion of entire ranges with new DeleteCommentModifierConfig format
    await executable_resource.run(
        DeleteCommentModifier,
        DeleteCommentModifierConfig(comment_range=Range(1, 2), comment_text=None),
    )
    comment_attributes = executable_resource.get_attributes(CommentsAttributes)
    assert get_comment_count(comment_attributes) == 5
    # Test deletion of entire ranges, with old DeleteCommentModifierConfig format
    await executable_resource.run(
        DeleteCommentModifier,
        DeleteCommentModifierConfig(comment_range=None),
    )
    comment_attributes = executable_resource.get_attributes(CommentsAttributes)
    assert get_comment_count(comment_attributes) == 2
    await executable_resource.run(
        DeleteCommentModifier,
        DeleteCommentModifierConfig(comment_range=Range(0, 2)),
    )
    comment_attributes = executable_resource.get_attributes(CommentsAttributes)
    assert get_comment_count(comment_attributes) == 0
    # Ensure none of the keys exist anymore
    assert len(comment_attributes.comments.keys()) == 0


async def test_deleting_non_existing_comment(executable_resource: Resource):
    """Test deleting non-existing comments."""
    with pytest.raises(NotFoundError):
        await executable_resource.run(
            DeleteCommentModifier,
            DeleteCommentModifierConfig(comment_range=(Range(0, 1))),
        )

    # Now test deleting a comment when no comments with that text exist
    await executable_resource.run(
        AddCommentModifier,
        AddCommentModifierConfig(comment=(None, "this exists")),
    )

    with pytest.raises(NotFoundError):
        await executable_resource.run(
            DeleteCommentModifier,
            DeleteCommentModifierConfig(comment_range=None, comment_text="this doesn't exist"),
        )

    await executable_resource.run(
        DeleteCommentModifier,
        DeleteCommentModifierConfig(comment_range=None, comment_text="this exists"),
    )

    comment_attributes = executable_resource.get_attributes(CommentsAttributes)
    assert get_comment_count(comment_attributes) == 0
