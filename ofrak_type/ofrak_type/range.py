from dataclasses import dataclass

import sys
from typing import Iterable, List


@dataclass
class Range:
    """
    Range of addresses.

    :ivar start: The start address of the Range
    :ivar end: The end address of the Range
    """

    start: int
    end: int

    MAX = sys.maxsize

    def __post_init__(self):
        if self.start > self.end:
            raise ValueError("The start value must be less than or equal to the end value")

    def __iter__(self):
        """
        Make this class iterable, allowing to write `for i in Range(...)` and `if i in Range(...)`.
        """
        yield from range(self.start, self.end)

    def __contains__(self, value):
        """
        Make the check `value in Range(...)` constant time.
        """
        return self.contains_value(value)

    def length(self):
        """
        Compute the length of this range
        """
        return self.end - self.start

    def contains_value(self, value: int) -> bool:
        """
        Determine if the provided value is within the range (inclusive of the start, exclusive of
        the end).

        Note: you can use `value in r` alternatively to `r.contains_value(value)`.
        """
        return self.start <= value < self.end

    def within(self, range: "Range") -> bool:
        """
        Determine if this range is within the provided range
        """
        return self.start >= range.start and self.end <= range.end

    def overlaps(self, range: "Range") -> bool:
        """
        Determine if this range overlaps the provided range.
        """
        return range.start < self.end and range.end > self.start

    def intersect(self, range: "Range") -> "Range":
        """
        Compute the largest possible range that is within both this range and the provided range.
        It raises a ValueError if no such range exists.
        """
        start = max(range.start, self.start)
        end = min(range.end, self.end)
        if start > end:
            raise ValueError("There is no overlap between this range and the provided range ")
        return Range(start, end)

    def split(self, range: "Range") -> Iterable["Range"]:
        """
        Split the range into one or more ranges that do not overlap the provided range
        :param range:
        :return:
        """
        if range.start >= self.end or range.end <= self.start:
            # No overlap
            return (self,)
        elif self.within(range):
            # This range is covered by the provided range
            return tuple()
        elif range.start <= self.start and range.end < self.end:
            # Overlap on the right
            return (Range(range.end, self.end),)
        elif range.start > self.start and range.end >= self.end:
            # Overlap on the left
            return (Range(self.start, range.start),)
        elif range.within(self):
            # The provided range sits in the middle of this range
            return Range(self.start, range.start), Range(range.end, self.end)
        else:
            raise ValueError("Unreachable")

    def translate(self, offset: int) -> "Range":
        """
        Generate a new range based on this range translated by the provided offset
        """
        if offset == 0:
            return self
        if offset + self.start < 0:
            raise ValueError("The start of the translated range cannot be negative")
        return Range(self.start + offset, self.end + offset)

    def __repr__(self) -> str:
        return f"Range({hex(self.start)}, {hex(self.end)})"

    def __hash__(self):
        return hash((self.start, self.end))

    @staticmethod
    def from_size(start: int, size: int) -> "Range":
        return Range(start, start + size)

    @staticmethod
    def merge_ranges(ranges: Iterable["Range"]) -> List["Range"]:
        """
        Merge multiple Ranges into a minimal set of Ranges. The algorithm here is basically
        finding where the input Ranges do NOT overlap, and inverting that.

        In more detail the algorithm is essentially:
        1. Iterates over all values from the minimum start to the maximum end while tracking a
        counter
        2. Increment the counter whenever the start of a range is reached, decrement the counter
        when the end of a range is reached
        3. Save a merged range when the counter is 0.

        It's more efficient than that since only range starts/ends are iterated over, but that's
        the idea.

        :param ranges: unordered iterable of Range objects to merge
        """
        range_bounds_markers = []
        for r in ranges:
            range_bounds_markers.append((r.start, 1))
            range_bounds_markers.append((r.end, -1))

        # Sort markers by index, and use inverted second item in tuple (incr) as tiebreaker
        # If start and end markers have the same index, the start marker(s) should be counted first
        range_bounds_markers.sort(key=lambda idx_incr: (idx_incr[0], -idx_incr[1]))

        merged_ranges = []
        current_overlapping_ranges = 0
        last_range_start = 0
        for idx, incr in range_bounds_markers:
            if current_overlapping_ranges == 0:
                # Must be at the start of a range
                last_range_start = idx
            current_overlapping_ranges += incr
            # The counter should never drop below zero
            assert current_overlapping_ranges >= 0, "Range bounds markers not ordered correctly"
            if current_overlapping_ranges == 0:
                # Must be at the end of a range
                merged_ranges.append(Range(last_range_start, idx))

        return merged_ranges


def chunk_ranges(ranges: List[Range], chunk_size: int) -> List[Range]:
    """
    Break a list of Ranges into equal sized regions of Ranges, assuming each range is evenly
    divisible by chunk_size.

    :param ranges:
    :param chunk_size:
    :return: equal sized regions of Ranges
    """
    regions = Range.merge_ranges(ranges)
    chunked = []
    for region in regions:
        for i in range(region.start, region.end, chunk_size):
            chunked.append(Range(i, min(i + chunk_size, region.end)))
    return chunked


def remove_subranges(ranges: List[Range], to_remove: List[Range]) -> List[Range]:
    """
    Subtract one set of addresses from another, both expressed as a list of non-overlapping ranges.

    :param ranges: A list of non-overlapping ranges.
    :param to_remove: A list of non-overlapping ranges to be removed from the first argument.
    :return: A list of ranges covering the input ranges with the subranges removed.
    """
    if not ranges or not to_remove:
        return ranges

    ranges.sort(key=lambda range_: range_.start)
    to_remove.sort(key=lambda range_: range_.start)

    i = 0
    j = 0
    ret = []
    current_range = ranges[i]
    current_to_remove = to_remove[j]
    while True:
        if current_range.start >= current_to_remove.end:
            j += 1
            if j < len(to_remove):
                current_to_remove = to_remove[j]
            else:
                ret.append(current_range)
                ret.extend(ranges[i + 1 :])
                break
        elif current_range.end <= current_to_remove.start:
            ret.append(current_range)
            i += 1
            if i < len(ranges):
                current_range = ranges[i]
            else:
                break

        elif current_range.start < current_to_remove.start:
            ret.append(Range(current_range.start, current_to_remove.start))
            current_range = Range(current_to_remove.start, current_range.end)

        elif current_range.end > current_to_remove.end:
            current_range = Range(current_to_remove.end, current_range.end)

        else:
            # current_to_remove contains current_range
            i += 1
            if i >= len(ranges):
                break
            current_range = ranges[i]

    return ret
