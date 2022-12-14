from abc import ABC, abstractmethod

from ofrak.service.abstract_ofrak_service import AbstractOfrakService


class IDServiceInterface(AbstractOfrakService, ABC):
    """
    The `IDServiceInterface` is an interface for a service that generates unique IDs.

    This interface is intended to be a singleton used to create IDs locally; if more than one
    instance of this service is going to be instantiated, then this service must be stateless and
    not rely on any internal state.
    """

    @abstractmethod
    def generate_id(self) -> bytes:
        """
        Generate a unique ID.

        This method guarantees that no two IDs it returns will be identical for the lifetime of
        the instantiated `IDServiceInterface`.

        :return: The unique ID that was generated.
        """
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def generate_id_from_base(base_id: bytes, key: str) -> bytes:
        """
        Generate an ID based on a base ID and key.

        This method returns the same ID each time it is called with the exact same parameters. It
        should therefore be used with caution: the callee needs to know that the parameters
        passed to this method are unique.

        :param bytes base_id: An ID used to derive the generated ID. This ID can be assumed to have
            been generated by the `generate_id` method.
        :param str key: A key used to guarantee that the generated ID is unique. The callee is
            responsible for ensuring that this key is unique.
        :return: The ID that was generated.
        """
        raise NotImplementedError()
