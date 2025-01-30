import argparse
from logging import DEBUG, INFO, WARNING, basicConfig
from typing import ClassVar

class Logging():
    FORMAT: ClassVar[str] = '%(asctime)s %(name)s: [%(levelname)s] %(message)s'
    DATEFMT: ClassVar[str] = '%b %d %H:%M:%S'
    loglevel: int

    def __init__(self, loglevel: int) -> None:
        self.loglevel = loglevel
        self.setup()

    def setup(self) -> None:
        basicConfig(
            format=self.FORMAT,
            datefmt=self.DATEFMT,
            level=self.loglevel,
        )

    @staticmethod
    def add_arguments(parser: argparse.ArgumentParser) -> None:
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

def add_logging_arguments(parser: argparse.ArgumentParser) -> None:
    Logging.add_arguments(parser)

