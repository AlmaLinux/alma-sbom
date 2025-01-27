import argparse
from abc import ABC, abstractmethod
from typing import Callable

from alma_sbom.cli.config import CommonConfig
from alma_sbom.cli.factory import CollectorFactory, DocumentFactory

class SubCommand(ABC):
    config: CommonConfig
    collector_factory: CollectorFactory
    document_factory: DocumentFactory
    runner: Callable

    @abstractmethod
    def run(self, args: argparse.Namespace) -> int:
        pass

    @abstractmethod
    def _select_runner() -> None:
        pass

