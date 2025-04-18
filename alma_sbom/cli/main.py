import argparse
import sys
from logging import getLogger

from alma_sbom.type import SbomType

from .logging import Logging, add_logging_arguments
from .commands import SubCommand, command_factory
from .config import CommonConfig, add_config_arguments

_logger = getLogger(__name__)

class Main:
    command: SubCommand
    args: argparse.Namespace
    config: CommonConfig

    def __init__(self, args: list[str]) -> None:
        parser = self.create_parser()
        self.args = parser.parse_args(args)
        logging = Logging(loglevel=self.args.loglevel)
        self.config = CommonConfig.from_args(self.args)
        self.command = command_factory(self.config, self.args)

    def run(self) -> int:
        return self.command.run()

    @staticmethod
    def create_parser() -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(description='alma-sbom')
        add_config_arguments(parser)
        add_logging_arguments(parser)
        return parser

def cli_main():
    args = sys.argv[1:]
    _main = Main(args)
    return _main.run()
