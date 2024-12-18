from abc import ABC, abstractmethod

from alma_sbom.data.models import Package, Build
from alma_sbom.config.config import CommonConfig

class Document(ABC):
    @classmethod
    @abstractmethod
    def from_package(cls, package: Package, config: CommonConfig) -> 'Document':
        pass

    @classmethod
    @abstractmethod
    def from_build(cls, build: Build, config: CommonConfig) -> 'Document':
        pass

    @abstractmethod
    def write(self) -> None:
        pass

