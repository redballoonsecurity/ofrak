from typing import Dict, Any

import json
import sys

import ofrak_type.error


class SerializedError(RuntimeError):
    def to_json(self):
        return json.dumps(self.to_dict(self))

    @classmethod
    def to_dict(cls, error: Exception):
        return {"type": type(error).__name__, "message": str(error)}

    @classmethod
    def from_json(cls, serialized: str) -> "SerializedError":
        error_dict = json.loads(serialized)
        error_type = error_dict["type"]
        try:
            error = getattr(sys.modules[__name__], error_type)
        except AttributeError:
            try:
                error = getattr(ofrak_type.error, error_type)
            except:
                raise ValueError(error_dict)
        if issubclass(error, cls):
            return error.from_dict({"message": error_dict["message"]})
        else:
            return error(error_dict["message"])

    @classmethod
    def from_dict(cls, error_dict: Dict[str, Any]) -> "SerializedError":
        return cls(error_dict["message"])


class DataServiceError(SerializedError):
    pass


class ResourceServiceError(SerializedError):
    pass


class JobServiceError(SerializedError):
    pass


class OutOfBoundError(DataServiceError):
    pass


class OverlapError(DataServiceError):
    def __init__(self, message, new_child_node: "DataNode", existing_child_node: "DataNode"):  # type: ignore
        super().__init__(message)
        self.new_child_node = new_child_node
        self.existing_child_node = existing_child_node


class PatchOverlapError(DataServiceError):
    pass


class MisalignedError(DataServiceError):
    pass


class AmbiguousOrderError(RuntimeError):
    pass


class NonContiguousError(DataServiceError):
    pass
