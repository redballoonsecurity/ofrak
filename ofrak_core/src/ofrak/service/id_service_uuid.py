import uuid

from ofrak.service.id_service_i import IDServiceInterface


class UUIDService(IDServiceInterface):
    def generate_id(self) -> bytes:
        # Note: pseudo-random
        return uuid.uuid4().bytes

    @staticmethod
    def generate_id_from_base(base_id: bytes, key: str) -> bytes:
        return uuid.uuid5(uuid.UUID(bytes=base_id), key).bytes
