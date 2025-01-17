import argparse
from dataclasses import dataclass
from enum import Enum
from typing import Union
from logging import getLogger

_logger = getLogger(__name__)

class SbomRecordType(Enum):
    SPDX = 'spdx'
    CYCLONEDX = 'cyclonedx'

    @classmethod
    def from_str(cls, string: str) -> 'SbomRecordType':
        for record_type in cls:
            if string == record_type.value:
                return record_type
        raise ValueError('Invalid SbomRecoredType string')

class SbomFileFormatType(Enum):
    JSON = 'json'
    TAGVALUE = 'tagvalue'
    XML = 'xml'
    YAML = 'yaml'

    @classmethod
    def from_str(cls, string: str) -> 'SbomFileFormatType':
        for record_format in cls:
            if string == record_format.value:
                return record_format
        raise ValueError('Invalid SbomFileFormatType string')

class SbomType:
    VALID_SBOM_TYPE: dict[SbomRecordType, list[SbomFileFormatType]] = {
        SbomRecordType.SPDX: [
            SbomFileFormatType.JSON,
            SbomFileFormatType.XML,
            SbomFileFormatType.YAML,
            SbomFileFormatType.TAGVALUE,
        ],
        SbomRecordType.CYCLONEDX: [
            SbomFileFormatType.JSON,
            SbomFileFormatType.XML,
        ],
    }
    record_type: SbomRecordType
    file_format_type: SbomFileFormatType

    def __init__(
        self,
        record_type: SbomRecordType = SbomRecordType.SPDX,
        file_format_type: SbomFileFormatType = SbomFileFormatType.JSON,
    ):
        self.record_type = record_type
        self.file_format_type = file_format_type
        self._validate()

    @classmethod
    def from_each_str(cls, record_type: str, file_format_type: str) -> 'SbomType':
        return cls(
            SbomRecordType.from_str(record_type),
            SbomFileFormatType.from_str(file_format_type),
        )

    @classmethod
    def from_str(cls, string: str) -> 'SbomType':
        try:
            record_type, file_format_type = string.split('-')
        except ValueError:
            raise argparse.ArgumentTypeError('Invalid SBOM type format. Use "record_type-file_format"')
        return cls.from_each_str(
            record_type,
            file_format_type,
        )

    def _validate(self) -> None:
        if self.file_format_type not in self.VALID_SBOM_TYPE[self.record_type]:
            raise ValueError(
                f"Invalid Sbom Type: "
                f"{self.record_type.value}-{self.file_format_type.value}"
            )

    @classmethod
    def choices(cls) -> list:
        return [f'{rt}-{ff}' for rt, ff in cls.get_valid_sbom_type()]

    @classmethod
    def get_valid_sbom_type(cls) -> list[tuple[str, str]]:
        return [
            (record_type.value, file_format.value)
            for record_type, file_formats in cls.VALID_SBOM_TYPE.items()
            for file_format in file_formats
        ]

    def values(self) -> tuple[Enum, ...]:
        return tuple([self.record_type, self.file_format_type])

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SbomType):
            return (
                self.record_type == other.record_type
                and self.file_format_type == other.file_format_type
            )
        return False

    def __repr__(self) -> str:
        return f"{self.record_type.value}-{self.file_format_type.value}"


@dataclass
class CommonConfig:
    ### output related settings ###
    ### TODO:
    # Is it OK to define default value in this class?
    # Wouldn't it be better to set default values in the places
    # where each class and/or function is implemented?
    output_file: str = '/dev/stdout'
    sbom_type: SbomType = SbomType(SbomRecordType.SPDX, SbomFileFormatType.JSON)

    ### ALBS/immudb settings ###
    albs_url: str = None
    immudb_username: str = None
    immudb_password: str = None
    immudb_database: str = None
    immudb_address: str = None
    immudb_public_key_file: str = None

    @classmethod
    def from_each_str(
        cls,
        output_file: str,
        sbom_record_type: str,
        sbom_file_format_type: str,
        albs_url: str,
        immudb_username: str,
        immudb_password: str,
        immudb_database: str,
        immudb_address: str,
        immudb_public_key_file: str,
    ) -> 'CommonConfig':
        return cls(
            output_file,
            SbomType.from_each_str(sbom_record_type, sbom_file_format_type),
            albs_url,
            immudb_username,
            immudb_password,
            immudb_database,
            immudb_address,
            immudb_public_key_file,
        )

    @classmethod
    def from_str(
        cls,
        output_file: str,
        sbom_type_str: str,
        albs_url: str,
        immudb_username: str,
        immudb_password: str,
        immudb_database: str,
        immudb_address: str,
        immudb_public_key_file: str,
    ) -> 'CommonConfig':
        return cls(
            output_file,
            SbomType.from_str(sbom_type_str),
            albs_url,
            immudb_username,
            immudb_password,
            immudb_database,
            immudb_address,
            immudb_public_key_file,
        )

    def __post_init__(self):
        pass

