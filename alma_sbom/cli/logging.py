import argparse
import logging
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
            help=('Print verbose output'),
            required=False,
            default=WARNING,
            action='store_const', dest='loglevel', const=INFO,
        )
        parser.add_argument(
            '--debug',
            help=('Print debug log'),
            required=False,
            action='store_const', dest='loglevel', const=DEBUG,
        )

def add_logging_arguments(parser: argparse.ArgumentParser) -> None:
    Logging.add_arguments(parser)

# ✅ ここから追加
def setup_logger(name: str = None) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s %(name)s: [%(levelname)s] %(message)s',
            datefmt='%b %d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger

