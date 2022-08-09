from dataclasses import dataclass
from typing import List, Iterable

import pytest
from hypothesis import strategies, given
from hypothesis.strategies import composite

from ofrak_type.range import Range, remove_subranges, chunk_ranges


@composite
def range_strategy(draw):
    start = draw(strategies.integers(min_value=0, max_value=2**32 - 1))
    end = draw(strategies.integers(min_value=start, max_value=2**32 - 1))
    return Range(start, end)


def test_invalid_range():
    with pytest.raises(ValueError):
        _ = Range(5, 0)


@given(r=range_strategy())
def test_length(r: Range):
    assert r.length() == r.end - r.start


@pytest.mark.parametrize(
    "r, value, expected_result",
    [
        (Range(0, 10), 0, True),
        (Range(0, 10), 5, True),
        (Range(0, 10), 10, False),
        (Range(0, 10), -1, False),
    ],
)
def test_contains(r: Range, value: int, expected_result: bool):
    assert r.contains_value(value) is expected_result
    # The `in` operator should also work:
    assert (value in r) is expected_result


@pytest.mark.parametrize(
    "range_1, range_2, expected_result",
    [
        (Range(2, 5), Range(0, 10), True),
        (Range(0, 10), Range(2, 5), False),
        (Range(5, 10), Range(0, 10), True),
        (Range(0, 2), Range(0, 10), True),
        (Range(0, 19), Range(5, 15), False),
    ],
)
def test_within(range_1: Range, range_2: Range, expected_result: bool):
    assert range_1.within(range_2) is expected_result


@pytest.mark.parametrize(
    "range_1, range_2, expected_result",
    [
        (Range(0, 10), Range(5, 15), True),
        (Range(0, 5), Range(5, 10), False),
        (Range(0, 10), Range(5, 7), True),
        (Range(5, 7), Range(0, 10), True),
    ],
)
def test_overlaps(range_1: Range, range_2: Range, expected_result: bool):
    assert range_1.overlaps(range_2) is expected_result


@pytest.mark.parametrize(
    "range_1, range_2, expected_range",
    [
        (Range(10, 20), Range(20, 30), Range(20, 20)),
        (Range(10, 20), Range(0, 30), Range(10, 20)),
        (Range(10, 20), Range(10, 30), Range(10, 20)),
        (Range(10, 20), Range(15, 30), Range(15, 20)),
    ],
)
def test_intersect(range_1: Range, range_2: Range, expected_range: Range):
    assert range_1.intersect(range_2) == expected_range


def test_intersect_value_error():
    range_1 = Range(10, 20)
    with pytest.raises(ValueError):
        range_1.intersect(Range(30, 40))


@pytest.mark.parametrize(
    "range_1, range_2, expected_result",
    [
        (Range(0, 10), Range(10, 20), (Range(0, 10),)),
        (Range(0, 1), Range(0, 1), ()),
        (Range(5, 10), Range(4, 9), (Range(9, 10),)),
        (Range(5, 10), Range(6, 11), (Range(5, 6),)),
        (
            Range(5, 10),
            Range(7, 8),
            (
                Range(5, 7),
                Range(8, 10),
            ),
        ),
    ],
)
def test_split(range_1: Range, range_2: Range, expected_result: Iterable[Range]):
    assert range_1.split(range_2) == expected_result


def test_split_value_error():
    """
    Test that the unreachable else statement at the end of Range.split raises a ValueError.
    """

    class RangeNeverWithin(Range):
        def within(self, range: Range) -> bool:
            return False

    range_1 = Range(5, 10)
    range_2 = RangeNeverWithin(7, 8)
    with pytest.raises(ValueError):
        range_1.split(range_2)


REMOVE_SUBRANGES_TEST_CASES = [
    (
        [Range(0x20, 0x40), Range(0x60, 0x80)],
        [Range(0x30, 0x50)],
        [Range(0x20, 0x30), Range(0x60, 0x80)],
    ),
    (
        [Range(0x20, 0x40), Range(0x60, 0x80)],
        [Range(0x50, 0x70)],
        [Range(0x20, 0x40), Range(0x70, 0x80)],
    ),
    (
        [Range(0x20, 0x40), Range(0x60, 0x80)],
        [Range(0x30, 0x70)],
        [Range(0x20, 0x30), Range(0x70, 0x80)],
    ),
    (
        [Range(0x20, 0x40), Range(0x60, 0x80)],
        [Range(0x00, 0x20), Range(0x40, 0x60), Range(0x80, 0xA0)],
        [Range(0x20, 0x40), Range(0x60, 0x80)],
    ),
    ([], [Range(0x20, 0x40)], []),
    ([Range(0x20, 0x40)], [], [Range(0x20, 0x40)]),
    ([Range(5, 10), Range(12, 14)], [Range(0, 20)], []),
]


@pytest.mark.parametrize("test_case", REMOVE_SUBRANGES_TEST_CASES)
def test_remove_subranges(test_case):
    ranges, to_remove, expected_result = test_case
    assert remove_subranges(ranges, to_remove) == expected_result


@pytest.mark.parametrize(
    "test_range, offset, expected_range",
    [
        (Range(0, 10), 0, Range(0, 10)),
        (Range(0, 10), 5, Range(5, 15)),
    ],
)
def test_translate(test_range: Range, offset: int, expected_range: Range):
    translated_range = test_range.translate(offset)
    assert translated_range == expected_range


@pytest.mark.parametrize("test_range, offset", [(Range(5, 10), -6)])
def test_translate_value_error(test_range: Range, offset: int):
    with pytest.raises(ValueError):
        test_range.translate(offset)


def test_repr():
    test_range = Range(5, 20)
    assert test_range.__repr__() == "Range(0x5, 0x14)"


def test_hash():
    """
    Test `Range.__hash__`, which is used in lookups like below.
    """
    range_set = {Range(10, 20)}
    assert Range(10, 20) in range_set


@given(start=strategies.integers(), size=strategies.integers(min_value=0))
def test_from_size(start: int, size: int):
    range_from_size = Range.from_size(start, size)
    assert range_from_size.start == start
    assert range_from_size.length() == size


MERGE_RANGES_TEST_CASES = [
    ("no ranges", [], []),
    ("single range", [Range(0, 10)], [Range(0, 10)]),
    (
        "non-overlapping ranges",
        [Range(0, 10), Range(12, 20)],
        [Range(0, 10), Range(12, 20)],
    ),
    (
        "simple adjacent ranges",
        [Range(0, 10), Range(10, 20)],
        [
            Range(0, 20),
        ],
    ),
    (
        "simple overlapping ranges",
        [Range(0, 12), Range(10, 20)],
        [
            Range(0, 20),
        ],
    ),
    (
        "many unordered overlapping ranges",
        [Range(90, 100), Range(35, 42), Range(10, 25), Range(85, 85), Range(80, 90), Range(20, 40)],
        [Range(10, 42), Range(80, 100)],
    ),
    (
        "ranges with negative starts/ends",
        [
            Range(-100, -90),
            Range(-42, -35),
            Range(-25, -10),
            Range(-85, -85),
            Range(-90, -80),
            Range(-40, -20),
        ],
        [Range(-100, -80), Range(-42, -10)],
    ),
    (
        "many duplicated ranges",
        [Range(0, 10), Range(10, 20), Range(10, 20), Range(10, 20), Range(10, 20), Range(10, 20)],
        [
            Range(0, 20),
        ],
    ),
    (
        "very large ranges",
        [Range(0, int(Range.MAX / 2)), Range(int(Range.MAX / 2), Range.MAX)],
        [
            Range(0, Range.MAX),
        ],
    ),
]


@pytest.mark.parametrize("test_case", MERGE_RANGES_TEST_CASES, ids=lambda tc: tc[0])
def test_merge_ranges(test_case):
    _, input_ranges, expected_merged_ranges = test_case

    merged_ranges = Range.merge_ranges(input_ranges)
    assert expected_merged_ranges == merged_ranges


@dataclass
class ChunkRangesTestCase:
    ranges: List[Range]
    chunck_size: int
    expected_output: List[Range]


RANGES_CHUNK_TEST_CASES = [
    ChunkRangesTestCase([Range(0, 2)], 1, [Range(0, 1), Range(1, 2)]),
    ChunkRangesTestCase([Range(0, 4)], 2, [Range(0, 2), Range(2, 4)]),
    ChunkRangesTestCase([Range(0, 4), Range(4, 8)], 2, [Range(i, i + 2) for i in range(0, 8, 2)]),
    ChunkRangesTestCase([Range(0, 4), Range(1, 3)], 2, [Range(0, 2), Range(2, 4)]),
    ChunkRangesTestCase([Range(0, 14)], 4, [Range(0, 4), Range(4, 8), Range(8, 12), Range(12, 14)]),
]


@pytest.mark.parametrize("test_case", RANGES_CHUNK_TEST_CASES)
def test_chunk_ranges(test_case: ChunkRangesTestCase):
    ranges = chunk_ranges(test_case.ranges, test_case.chunck_size)
    assert ranges == test_case.expected_output


def test_range_iterable():
    r = Range(10, 12)
    # This should return without raising a TypeError if `r` is iterable.
    iter(r)
    # Also verify isinstance() recognizes Range as iterable
    assert isinstance(r, Iterable)


def test_range_iterable_for_loop():
    """Test that Range behaves like an iterable, notably in for loops."""
    r = Range(10, 12)
    # Test that the same object can be iterated over several times
    for iteration in range(2):
        range_iterated_items = [i for i in r]
        assert range_iterated_items == list(range(10, 12))
