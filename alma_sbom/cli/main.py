import argparse
import sys
from logging import DEBUG, INFO, WARNING, getLogger, Logger

from .logging import Logging
from .commands import SubCommand, setup_subparsers, command_factory
from alma_sbom.type import SbomType
from .config.config import CommonConfig

_logger = getLogger(__name__)

class Main:
    command: SubCommand
    args: argparse.Namespace
    config: CommonConfig
    #logging: Logging
    #logger: Logger

    def __init__(self, args: list[str]) -> None:
        parser = create_parser()
        self.args = parser.parse_args(args)
        logging = Logging(loglevel=self.args.loglevel)
        self.config = self._get_CommonConfig_from_args(self.args)
        self.command = command_factory(self.config, self.args)

    def _get_CommonConfig_from_args(self, args: argparse.Namespace) -> CommonConfig:
        return CommonConfig.from_str(
            args.output_file,
            args.file_format,
            args.albs_url,
            args.immudb_username,
            args.immudb_password,
            args.immudb_database,
            args.immudb_address,
            args.immudb_public_key_file,
        )

    def run(self) -> int:
        _logger.debug('Hello from Main.run')
        _logger.debug(f'CommonConfig: {self.config}')
        return self.command.run()

def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='alma-sbom')

    ### output related settings ###
    parser.add_argument(
        '--output-file',
        type=str,
        help=(
            'Full path to an output file with SBOM. Output will be '
            'to stdout if the parameter is absent or emtpy'
        ),
        required=False,
        default='/dev/stdout',
    )
    parser.add_argument(
        '--file-format',
        default=str(SbomType()),
        const=SbomType(),
        nargs='?',
        choices=SbomType.choices(),
        type=str,
        help='Generate SBOM in one of format mode (default: %(default)s)',
    )

    ### ALBS/immudb settings ###
    parser.add_argument(
        '--albs-url',
        type=str,
        help='Override ALBS url',
    )
    parser.add_argument(
        '--immudb-username',
        type=str,
        help=(
            'Provide your immudb username if not set as '
            'an environmental variable'
        ),
        required=False,
    )
    parser.add_argument(
        '--immudb-password',
        type=str,
        help=(
            'Provide your immudb password if not set as '
            'an environmental variable'
        ),
        required=False,
    )
    parser.add_argument(
        '--immudb-database',
        type=str,
        help=(
            'Provide your immudb database if not set as '
            'an environmental variable'
        ),
        required=False,
    )
    parser.add_argument(
        '--immudb-address',
        type=str,
        help=(
            'Provide your immudb address if not set as '
            'an environmental variable'
        ),
        required=False,
    )
    parser.add_argument(
        '--immudb-public-key-file',
        type=str,
        help=(
            'Provide your immudb public key file if not set as '
            'an environmental variable'
        ),
        required=False,
    )

    # ### extra fields options ###
    # parser.add_argument(
    #     '--creator-name-person',
    #     type=str,
    #     action='append',
    #     help=(
    #         'The person(s) who create SBOM'
    #     ),
    #     required=False,
    #     default=[],
    # )
    # parser.add_argument(
    #     '--creator-email-person',
    #     type=str,
    #     action='append',
    #     help=(
    #         'The email address of SBOM creator. '
    #         'This option is only required if --creator-name-personal is provided. '
    #         'The combination of name and email address depends on the order specified. '
    #         'If an extra email address is specified, it will be ignored'
    #     ),
    #     required=False,
    #     default=[],
    # )
    # parser.add_argument(
    #     '--creator-name-org',
    #     type=str,
    #     action='append',
    #     help=(
    #         'The organization(s) who create SBOM'
    #     ),
    #     required=False,
    #     default=[],
    # )
    # parser.add_argument(
    #     '--creator-email-org',
    #     type=str,
    #     action='append',
    #     help=(
    #         'The email address of SBOM creator. '
    #         'This option is only required if --creator-name-org is provided. '
    #         'The combination of name and email address depends on the order specified. '
    #         'If an extra email address is specified, it will be ignored.'
    #     ),
    #     required=False,
    #     default=[],
    # )

    ### logging settings ###
    parser.add_argument(
        '--verbose',
        help=(
            'Print verbose output'
        ),
        required=False,
        default=WARNING,
        action='store_const', dest='loglevel', const=INFO,
    )
    parser.add_argument(
        '--debug',
        help=(
            'Print debug log'
        ),
        required=False,
        action='store_const', dest='loglevel', const=DEBUG,
    )

    ### subcommand settings using setup_subparsers ###
    subparsers = parser.add_subparsers(dest='command', required=True)
    setup_subparsers(subparsers)

    return parser

def cli_main():
    args = sys.argv[1:]
    _main = Main(args)
    return _main.run()
