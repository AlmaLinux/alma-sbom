from abc import ABC, abstractmethod

from alma_sbom.data.models import Package, Build, Iso
from alma_sbom.type import SbomFileFormatType

class Document(ABC):
    @classmethod
    @abstractmethod
    def from_package(cls, package: Package, file_format_type: SbomFileFormatType) -> 'Document':
        pass

    @classmethod
    @abstractmethod
    def from_build(cls, build: Build, file_format_type: SbomFileFormatType) -> 'Document':
        pass

    @classmethod
    @abstractmethod
    def from_iso(cls, iso: Iso, file_format_type: SbomFileFormatType) -> 'Document':
        pass

    @abstractmethod
    def write(self, output_file: str) -> None:
        pass

