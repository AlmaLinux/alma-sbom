import argparse
from abc import ABC, abstractmethod
from typing import Callable, ClassVar

from alma_sbom.cli.config import CommonConfig
from alma_sbom.cli.factory import CollectorFactory, DocumentFactory

class SubCommand(ABC):
    CONFIG_CLASS : ClassVar[type[CommonConfig]]

    config: CommonConfig
    collector_factory: CollectorFactory
    document_factory: DocumentFactory
    runner: Callable

    def __init__(self, base: CommonConfig, args: argparse.Namespace) -> None:
        self.config = self.CONFIG_CLASS.from_base_args(base, args)
        self.collector_factory = CollectorFactory(self.config)
        self.document_factory = DocumentFactory(self.config)
        self._select_runner()

    @abstractmethod
    def run(self, args: argparse.Namespace) -> int:
        pass

    @abstractmethod
    def _select_runner() -> None:
        pass

