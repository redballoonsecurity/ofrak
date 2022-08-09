from ofrak_type.range import Range
from ofrak.model.data_model import DataPatch
from ofrak.service.data_service import DataService
from test_ofrak.service.data_service.data_service_test import DATA_5


class TestSavePoints:
    async def test_savepoints(self, populated_data_service: DataService):
        initial_patches = [
            DataPatch(
                Range(0x0, 0x4),
                DATA_5,
                b"\x11" * 4,
            ),
        ]

        next_patches = [
            DataPatch(
                Range(0x0, 0x2),
                DATA_5,
                b"\x22" * 2,
            ),
            DataPatch(
                Range(0x4, 0x6),
                DATA_5,
                b"\x22" * 2,
            ),
        ]

        await populated_data_service.apply_patches(initial_patches)
        first_savepoint: str = await populated_data_service.create_savepoint()
        await populated_data_service.apply_patches(next_patches)
        second_savepoint: str = await populated_data_service.create_savepoint()

        patches_between_savepoints = await populated_data_service.get_patches_between_savepoints(
            first_savepoint,
            second_savepoint,
        )

        assert [next_patches] == patches_between_savepoints

    async def test_trivial_diff(self, populated_data_service: DataService):
        initial_patches = [
            DataPatch(
                Range(0x0, 0x4),
                DATA_5,
                b"\x11" * 4,
            ),
        ]

        await populated_data_service.apply_patches(initial_patches)
        first_savepoint: str = await populated_data_service.create_savepoint()
        second_savepoint: str = await populated_data_service.create_savepoint()
        assert first_savepoint == second_savepoint
