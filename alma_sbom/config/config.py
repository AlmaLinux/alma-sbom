import argparse
from dataclasses import dataclass
from enum import Enum
from typing import Union
from logging import getLogger

from alma_sbom.type import SbomRecordType, SbomFileFormatType, SbomType

_logger = getLogger(__name__)

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

