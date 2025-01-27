import argparse
import sys
from logging import DEBUG, INFO, WARNING, getLogger, Logger

from alma_sbom.type import SbomType

from .logging import Logging
from .commands import SubCommand, command_factory
from .config import CommonConfig, add_config_arguments

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
        self.config = CommonConfig.from_args(self.args)
        self.command = command_factory(self.config, self.args)

    def run(self) -> int:
        _logger.debug('Hello from Main.run')
        _logger.debug(f'CommonConfig: {self.config}')
        return self.command.run()

def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='alma-sbom')
    add_config_arguments(parser)

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

    return parser

def cli_main():
    args = sys.argv[1:]
    _main = Main(args)
    return _main.run()
