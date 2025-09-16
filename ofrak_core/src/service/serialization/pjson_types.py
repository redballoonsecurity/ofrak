from typing import Dict, Any, List, Tuple, Type, Set, Optional, Union

# Under-approximation of the PJSON type (which is recursive, contrary to this definition).
# All objects of the real PJSON type will be of this type, but some non-PJSON objects will
# also be of this type.
PJSONType = Union[str, int, float, bool, None, Dict[str, Any], List[Any], Tuple[Any, ...]]

# The containers we descend into
ContainerType = Union[
    Optional[Any], Dict[Any, Any], List[Any], Tuple[Any, ...], Set[Any], Type[Any]
]
