from abc import ABC, abstractmethod
from typing import Union

from alma_sbom.data import Package, Build
from alma_sbom.config.config import CommonConfig

class CollectorRunner(ABC):
    config: CommonConfig

    def __init__(self, config: CommonConfig):
        self.config = config

    @abstractmethod
    def run(self) -> Union[Package, Build]:
        pass

