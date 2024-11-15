__all__ = ["NotFoundError", "AlreadyExistError", "InvalidStateError", "InvalidUsageError"]


class NotFoundError(RuntimeError):
    pass


class AlreadyExistError(RuntimeError):
    pass


class InvalidStateError(RuntimeError):
    pass


class InvalidUsageError(RuntimeError):
    pass
