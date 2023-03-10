from typing import Any, Dict, Tuple, Type, Union

from ofrak.core.patch_maker.modifiers import PatchFromSourceModifierConfig
from ofrak.service.serialization.pjson_types import PJSONType

from ofrak.service.serialization.serializers.serializer_i import SerializerInterface
from ofrak_patch_maker.toolchain.abstract import Toolchain
from ofrak_patch_maker.toolchain.model import Segment, ToolchainConfig


class PatchFromSourceModifierConfigSerializer(SerializerInterface):
    """
    Serialize and deserialize `PatchFromSourceModifierConfig` into `PJSONType`.

    Implementation: sets are serialized as lists.
    """

    targets = ()

    def obj_to_pjson(self, obj: PatchFromSourceModifierConfig, type_hint: Any) -> PJSONType:
        as_dict = {
            "source_code": obj.source_code,
            "source_patches": self._service.to_pjson(
                obj.source_patches, Dict[str, Tuple[Segment, ...]]
            ),
            "toolchain_config": self._service.to_pjson(obj.toolchain_config, ToolchainConfig),
            "toolchain": self._service.to_pjson(obj.toolchain, Type[Toolchain]),
            "patch_name": obj.patch_name,
            "header_directories": obj.header_directories,
            "_source_code_slurped": self._service.to_pjson(
                obj.source_code_slurped, Dict[str, Union[str, Dict]]
            ),
            "_header_directories_slurped": self._service.to_pjson(
                obj.header_directories_slurped, Tuple[Dict[str, Union[str, Dict]], ...]
            ),
        }

        return as_dict

    def pjson_to_obj(self, pjson_obj: PJSONType, type_hint: Any) -> PatchFromSourceModifierConfig:

        cfg = object.__new__(PatchFromSourceModifierConfig)

        cfg.source_code = pjson_obj["source_code"]
        cfg.source_patches = self._service.from_pjson(
            pjson_obj["source_patches"], Dict[str, Tuple[Segment, ...]]
        )
        cfg.toolchain_config = self._service.from_pjson(
            pjson_obj["toolchain_config"], ToolchainConfig
        )
        cfg.toolchain = self._service.from_pjson(pjson_obj["toolchain"], Type[Toolchain])
        cfg.patch_name = pjson_obj["patch_name"]
        cfg.header_directories = self._service.from_pjson(
            pjson_obj["header_directories"], Tuple[str, ...]
        )
        cfg.source_code_slurped = self._service.from_pjson(
            pjson_obj["_source_code_slurped"], Dict[str, Union[str, Any]]
        )
        cfg.header_directories_slurped = self._service.from_pjson(
            pjson_obj["_header_directories_slurped"], Tuple[Dict[str, Union[str, Any]], ...]
        )

        return cfg
