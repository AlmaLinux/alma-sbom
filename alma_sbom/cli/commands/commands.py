import argparse
from abc import ABC, abstractmethod
from typing import Type, Dict

#from . import command_classes

class SubCommand(ABC):
    @abstractmethod
    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        pass

    @abstractmethod
    def execute(self, args: argparse.Namespace) -> None:
        pass

