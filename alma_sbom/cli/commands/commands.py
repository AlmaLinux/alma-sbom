import argparse
from abc import ABC, abstractmethod
from typing import Type, Dict

from alma_sbom.config.config import CommonConfig
from alma_sbom.formats.document import Document

class SubCommand(ABC):
    config: CommonConfig
    doc: Document

    @staticmethod
    @abstractmethod
    def add_arguments(parser: argparse.ArgumentParser) -> None:
        pass

    @abstractmethod
    def run(self, args: argparse.Namespace) -> int:
        pass

