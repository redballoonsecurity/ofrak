class NotFoundError(RuntimeError):
    pass


class MultipleResourcesFoundError(RuntimeError):
    pass


class AlreadyExistError(RuntimeError):
    pass


class InvalidStateError(RuntimeError):
    pass


class InvalidUsageError(RuntimeError):
    pass
