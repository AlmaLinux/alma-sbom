import argparse
from abc import ABC, abstractmethod
from typing import Callable

from ..config.config import CommonConfig
from alma_sbom.formats.document import Document

class SubCommand(ABC):
    config: CommonConfig
    doc: Document
    collector_runner: Callable

    @abstractmethod
    def run(self, args: argparse.Namespace) -> int:
        pass

    @abstractmethod
    def _select_runner() -> None:
        pass

