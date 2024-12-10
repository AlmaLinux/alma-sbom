import argparse
from abc import ABC, abstractmethod
from typing import Type, Dict

from ...config.config import CommonConfig

class SubCommand(ABC):
    config: CommonConfig

    @staticmethod
    @abstractmethod
    def add_arguments(parser: argparse.ArgumentParser) -> None:
        pass

    @abstractmethod
    def run(self, args: argparse.Namespace) -> int:
        pass

