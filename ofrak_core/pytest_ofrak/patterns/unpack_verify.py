import warnings
from abc import abstractmethod, ABC
from dataclasses import dataclass
from typing import Any, Dict, Generic, TypeVar, Set, Iterable

import pytest

from ofrak import OFRAKContext
from ofrak.resource import Resource

K = TypeVar("K")
V = TypeVar("V")


def _hexlify(x):
    if isinstance(x, Iterable):
        return [hex(y) if isinstance(y, int) else y for y in x]
    return hex(x) if isinstance(x, int) else x


@dataclass
class UnpackAndVerifyTestCase(Generic[K, V]):
    """
    Container for test cases which will be fed to an UnpackAndVerifyPattern implementation.
    Extend this class, adding some fields to hold the information needed to create the root
    resource for each test case.

    Test cases are organized into "expected" and "optional" results.
      - Expected results are required to exist in the unpacker output following the test
        procedure. The lack of any expected result fails the test.
      - Optional results may or may not exist in the unpacker output. The lack of an optional
        result generates a warning.
      - Results which aren't specified in either 'expected' or 'optional' sets fail the test.

    :param K: The key type of the expected and optional results. The unpacked resources will each be assigned
    a key of this same type, allowing the test to match actual unpacked resources with expected
    values.
    :param V: The value type of the expected and optional results. This can be anything, as long as it
    contains the information needed to verify that the actual unpacked resource matches what is
    expected.
    """

    label: str
    expected_results: Dict[K, V]
    optional_results: Dict[K, V]


class UnpackAndVerifyPattern(ABC):
    """
    Test pattern for unpackers. The test expects to:
    1. Receive some parameterized test cases (fixture ``unpack_verify_test_case``)
    2. From each test case:
        a) Instantiate a root resource to unpack (fixture ``root_resource``)
        b) Extract the expected results (fixture ``expected_results``)
        c) Extract the optional results (fixture ``optional_results``)
    3. Unpack the root resource (method ``unpack``)
    4. Get the descendants of the unpacked root resource (method ``get_descendants_to_verify``)
    5. Test that the descendants match the expected and optional results, (method ``test_unpack_verify``), as follows:
        - Assert that all expected results exist as descendants of the unpacked resource
        - Assert that there are no descendants that are neither in the expected results nor in the optional results
        - Warn if any optional results do not exist as descendants of the unpacked resource

    Each step is broken out into a method. Some of the methods are abstract and need to be
    implemented in classes implementing this test pattern; others already implemented and only
    need to be re-implemented (overridden) in specific circumstances, explained in each method.
    """

    async def test_unpack_verify(
        self,
        root_resource: Resource,
        expected_results: Dict,
        optional_results: Dict,
    ):
        await self.unpack(root_resource)
        print(await root_resource.summarize_tree())

        ## Prepare results for comparison
        unpacked_results = await self.get_descendants_to_verify(root_resource)
        unpacked_set = set(unpacked_results.keys())

        expected_set = set(expected_results.keys())
        optional_set = set(optional_results.keys())

        unpacked_expected_set = unpacked_set & expected_set
        unpacked_optional_set = unpacked_set & optional_set

        # Optional entries are allowed to be absent from the unpacker results, so we warn
        # about them instead.
        missing_optional_set = optional_set - unpacked_set

        ## Build an info string about this test case
        info_str = [f"{'item':<16}{'unpacked':<16}{'expected':<16}{'optional':<16}"]
        for item in unpacked_set | expected_set | optional_set:
            item_fmt = str(_hexlify(item))
            row = (
                f"{item_fmt:<16}"
                f"{item_fmt if item in unpacked_set else '':<16}"
                f"{item_fmt if item in expected_set else '':<16}"
                f"{item_fmt if item in optional_set else '':<16}"
            )
            info_str.append(row)
        info_str = "\n".join(info_str)

        ## Sanity check to ensure that optional and expected sets are exclusive
        assert expected_set & optional_set == set(), (
            f"{_hexlify(expected_set & optional_set)} cannot be both expected and optional!\n"
            f"{info_str}"
        )

        ## Verify cardinality of expected descendants and unpacked descendants
        self.verify_expected_descendants(unpacked_expected_set, expected_set, info_str)

        ## Verify that there are no results outside the (expected | optional) sets
        self.verify_no_extraneous_descendants(unpacked_set, expected_set, optional_set, info_str)

        ## Verify the value of each expected descendant
        for key in expected_set:
            await self.verify_descendant(unpacked_results[key], expected_results[key])

        ## Verify the value of each unpacked optional descendant
        for key in unpacked_optional_set:
            await self.verify_descendant(unpacked_results[key], optional_results[key])

        ## Warn if there are missing optional results
        if missing_optional_set:
            warnings.warn(
                UserWarning(
                    f"The following optional functions are missing from the analyzer results: "
                    f"{_hexlify(sorted(missing_optional_set))}\n"
                    f"{info_str}"
                )
            )

    @pytest.fixture(params=[], ids=lambda tc: tc.label)
    @abstractmethod
    async def unpack_verify_test_case(self, request) -> UnpackAndVerifyTestCase:
        """
        Gathers all the test cases for a test class implementing this pattern

        Override this method to specify the parametrized test cases. The overriding method should
        look exactly the same as this base method, except with a list of actual test cases
        supplied to the ``params`` in the fixture decorator. The type of this list should be
        List[UnpackAndVerifyTestCase]
        """
        return request.param

    @pytest.fixture
    @abstractmethod
    async def root_resource(
        self,
        unpack_verify_test_case: UnpackAndVerifyTestCase,
        ofrak_context: OFRAKContext,
        test_id: str,
    ) -> Resource:
        """
        Instantiate a root resource for this test
        """
        raise NotImplementedError()

    @pytest.fixture
    async def expected_results(
        self, unpack_verify_test_case: UnpackAndVerifyTestCase[K, V]
    ) -> Dict[K, V]:
        """
        Extract the expected results from the test case.

        Override this method if for some reason the expected results need to be modified in some way
        before being passed to the test. If the expected results are good as-is, do not override
        this method.
        """
        return unpack_verify_test_case.expected_results

    @pytest.fixture
    async def optional_results(
        self, unpack_verify_test_case: UnpackAndVerifyTestCase[K, V]
    ) -> Dict[K, V]:
        """
        Extract the optional results from the test case.

        Override this method if for some reason the optional results need to be modified in some way
        before being passed to the test. If the optional results are good as-is, do not override
        this method.
        """
        return unpack_verify_test_case.optional_results

    @abstractmethod
    async def unpack(self, root_resource: Resource):
        """
        Unpack the root resource
        """
        raise NotImplementedError()

    @abstractmethod
    async def get_descendants_to_verify(self, unpacked_root_resource: Resource) -> Dict:
        """
        Once the root resource has been unpacked, get some set of descendants of the root
        resource to check against the expected results. A key should be calculated for each of
        these resources. This key should match the type K in the UnpackAndVerifyTestCase type
        this test uses, because it will be used to look up the expected result for each
        descendant in the test case.

        :returns: Dict[K, V] where K and V match the type parameters to the
        UnpackAndVerifyTestCase type for this test
        """
        raise NotImplementedError()

    @abstractmethod
    async def verify_descendant(self, unpacked_descendant: Any, specified_result: Any):
        """
        Verify that the actual unpacked descendant matches the specified result from the test case
        """
        raise NotImplementedError()

    def verify_expected_descendants(
        self, unpacked_set: Set, expected_set: Set, info_str: str = f""
    ):
        """
        Assert that the resources returned by ``get_descendants_to_verify`` (unpacked_set)
        match all values specified in ``expected_set``.

        Override to allow for unpacked results with missing expected values.
        """

        assert expected_set - unpacked_set == set(), (
            f"unpacked descendants {_hexlify(unpacked_set)} did not match expected {_hexlify(expected_set)}\n"
            f"missing results: {_hexlify(expected_set - unpacked_set)}\n"
            f"{info_str}"
        )

    def verify_no_extraneous_descendants(
        self,
        unpacked_set: Set,
        expected_set: Set,
        optional_set: Set,
        info_str: str = f"",
    ):
        """
        Assert that the resources returned by ``get_descendants_to_verify`` (unpacked_set)
        are all covered by an expected or optional test case.

        Override to allow unpacked values beyond the scope of (expected | optional) cases.
        """
        full_set = expected_set | optional_set
        unpacked_extraneous_set = unpacked_set - full_set

        assert unpacked_extraneous_set == set(), (
            f"Unpacked descendant(s) {_hexlify(unpacked_extraneous_set)} "
            f"outside the range of expected + optional descendants.\n"
            f"{info_str}"
        )
