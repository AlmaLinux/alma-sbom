import argparse
import os
from dataclasses import dataclass
from enum import Enum
from typing import Union, ClassVar
from logging import getLogger

from immudb_wrapper import ImmudbWrapper

from alma_sbom.type import SbomRecordType, SbomFileFormatType, SbomType

_logger = getLogger(__name__)

@dataclass
class CommonConfig:
    ### output related defaults ###
    DEF_OUTPUT: ClassVar[str] = '/dev/stdout'
    DEF_SBOM_TYPE: ClassVar[SbomType] = SbomType()
    DEF_SBOM_TYPE_STR: ClassVar[str] = str(SbomType())

    ### ALBS defaults ###
    DEF_ALBS_URL: ClassVar[str] = 'https://build.almalinux.org'

    ### immudb defaults ###
    DEF_IMMUDB_USERNAME: ClassVar[str] = os.getenv('IMMUDB_USERNAME') or ImmudbWrapper.read_only_username()
    DEF_IMMUDB_PASSWORD: ClassVar[str] = os.getenv('IMMUDB_PASSWORD') or ImmudbWrapper.read_only_password()
    DEF_IMMUDB_DATABASE: ClassVar[str] = os.getenv('IMMUDB_DATABASE') or ImmudbWrapper.almalinux_database_name()
    DEF_IMMUDB_ADDRESS: ClassVar[str] = os.getenv('IMMUDB_ADDRESS') or ImmudbWrapper.almalinux_database_address()
    DEF_IMMUDB_PUBLIC_KEY_FILE: ClassVar[str] = os.getenv('IMMUDB_PUBLIC_KEY_FILE')

    ### output related settings ###
    output_file: str
    sbom_type: SbomType

    ### ALBS settings ###
    albs_url: str

    ### immudb settings ###
    immudb_username: str
    immudb_password: str
    immudb_database: str
    immudb_address: str
    immudb_public_key_file: str

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

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> 'CommonConfig':
        return cls.from_str(
            args.output_file,
            args.file_format,
            args.albs_url,
            args.immudb_username,
            args.immudb_password,
            args.immudb_database,
            args.immudb_address,
            args.immudb_public_key_file,
        )

    def __post_init__(self):
        pass

    @classmethod
    def add_arguments(cls, parser: argparse.ArgumentParser) -> None:
        cls._add_output_arguments(parser)
        cls._add_albs_arguments(parser)
        cls._add_immudb_arguments(parser)

    @classmethod
    def _add_output_arguments(cls, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            '--output-file',
            type=str,
            help=(
                'Full path to an output file with SBOM. Output will be '
                'to stdout if the parameter is absent or emtpy'
            ),
            required=False,
            default=cls.DEF_OUTPUT,
        )
        parser.add_argument(
            '--file-format',
            default=cls.DEF_SBOM_TYPE_STR,
            choices=SbomType.choices(),
            type=str,
            help='Generate SBOM in one of format mode (default: %(default)s)',
        )

    @classmethod
    def _add_albs_arguments(cls, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            '--albs-url',
            type=str,
            help='Override ALBS url',
            default=cls.DEF_ALBS_URL,
        )

    @classmethod
    def _add_immudb_arguments(cls, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            '--immudb-username',
            type=str,
            help=(
                'Provide your immudb username if not set as '
                'an environmental variable'
            ),
            required=False,
            default=cls.DEF_IMMUDB_USERNAME
        )
        parser.add_argument(
            '--immudb-password',
            type=str,
            help=(
                'Provide your immudb password if not set as '
                'an environmental variable'
            ),
            required=False,
            default=cls.DEF_IMMUDB_PASSWORD
        )
        parser.add_argument(
            '--immudb-database',
            type=str,
            help=(
                'Provide your immudb database if not set as '
                'an environmental variable'
            ),
            required=False,
            default=cls.DEF_IMMUDB_DATABASE
        )
        parser.add_argument(
            '--immudb-address',
            type=str,
            help=(
                'Provide your immudb address if not set as '
                'an environmental variable'
            ),
            required=False,
            default=cls.DEF_IMMUDB_ADDRESS
        )
        parser.add_argument(
            '--immudb-public-key-file',
            type=str,
            help=(
                'Provide your immudb public key file if not set as '
                'an environmental variable'
            ),
            required=False,
            default=cls.DEF_IMMUDB_PUBLIC_KEY_FILE
        )

    #@classmethod
    #def _add_extra_field_arguments(cls, parser: argparse.ArgumentParser) -> None:
    #     parser.add_argument(
    #         '--creator-name-person',
    #         type=str,
    #         action='append',
    #         help=(
    #             'The person(s) who create SBOM'
    #         ),
    #         required=False,
    #         default=[],
    #     )
    #     parser.add_argument(
    #         '--creator-email-person',
    #         type=str,
    #         action='append',
    #         help=(
    #             'The email address of SBOM creator. '
    #             'This option is only required if --creator-name-personal is provided. '
    #             'The combination of name and email address depends on the order specified. '
    #             'If an extra email address is specified, it will be ignored'
    #         ),
    #         required=False,
    #         default=[],
    #     )
    #     parser.add_argument(
    #         '--creator-name-org',
    #         type=str,
    #         action='append',
    #         help=(
    #             'The organization(s) who create SBOM'
    #         ),
    #         required=False,
    #         default=[],
    #     )
    #     parser.add_argument(
    #         '--creator-email-org',
    #         type=str,
    #         action='append',
    #         help=(
    #             'The email address of SBOM creator. '
    #             'This option is only required if --creator-name-org is provided. '
    #             'The combination of name and email address depends on the order specified. '
    #             'If an extra email address is specified, it will be ignored.'
    #         ),
    #         required=False,
    #         default=[],
    #     )

