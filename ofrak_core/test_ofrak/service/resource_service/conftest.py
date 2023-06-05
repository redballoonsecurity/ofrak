from dataclasses import dataclass
from typing import Optional, List, Union, Tuple, Iterable


from ofrak.model.resource_model import (
    ResourceModel,
    ResourceTag,
    ResourceAttributes,
)
from ofrak.service.resource_service_i import (
    ResourceFilter,
    ResourceSort,
    ResourceServiceInterface,
)


@dataclass
class GetAncestorsTestCase:
    label: str
    resource_id: bytes
    expected_results: List[bytes]
    max_count: int = -1
    r_filter: Optional[ResourceFilter] = None


@dataclass
class GetDescendantsTestCase:
    label: str
    resource_id: bytes
    expected_results: Union[List[bytes], List[List[bytes]]]
    max_count: int = -1
    max_depth: int = -1
    r_filter: Optional[ResourceFilter] = None
    r_sort: Optional[ResourceSort] = None
    extra_resources: Optional[
        List[Tuple[Iterable[ResourceTag], Iterable[ResourceAttributes]]]
    ] = None

    async def initialize(self, resource_service: ResourceServiceInterface):
        if self.extra_resources is None:
            return

        for i, (tags, attributes) in enumerate(self.extra_resources):
            r_id = bytes(i)
            await resource_service.create(
                ResourceModel.create(
                    r_id,
                    None,
                    None,
                    tags,
                    attributes,
                )
            )

    def check_results(self, results: List[ResourceModel]):
        n_results = len(results)
        unique_results = {model.id for model in results}
        assert len(unique_results) == n_results
        assert len(unique_results) == len(self.expected_results)

        assert all([expected_result in unique_results for expected_result in self.expected_results])
        assert all([result in self.expected_results for result in unique_results]), unique_results


class GetDescendantsTestCaseMultipleResults(GetDescendantsTestCase):
    def check_results(self, results: List[ResourceModel]):
        n_results = len(results)
        unique_results = {model.id for model in results}
        assert len(unique_results) == n_results

        assertion_errors = []
        for expected_results in self.expected_results:
            try:
                assert len(unique_results) == len(expected_results)
                assert all(
                    [expected_result in unique_results for expected_result in expected_results]
                )
                assert all([result in expected_results for result in unique_results])

                return
            except AssertionError as e:
                assertion_errors.append(e)

        raise Exception(assertion_errors)


class GetDescendantsTestCaseOrderedResults(GetDescendantsTestCase):
    def check_results(self, results: List[ResourceModel]):
        # We get an ordered list of results, which we compare to self.expected_results.
        # However some expected results have the same value wrt the sorting function, so
        # self.expected_results is actually a list of lists, each sublist containing elements
        # that are equivalent in this way.
        results = list(model.id for model in results)
        assert len(results) == sum(len(x) for x in self.expected_results)
        for i in range(len(self.expected_results)):
            # Use a copy of self.expected_results[i] before modifying it, since pytest might reuse the
            # same object for subsequent iterations of testing.
            current_expected_results: List[bytes] = self.expected_results[i][:]
            while len(current_expected_results) > 0:
                next_result = results.pop(0)
                assert next_result in current_expected_results
                current_expected_results.remove(next_result)
