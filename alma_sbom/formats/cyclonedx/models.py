from enum import Enum
from cyclonedx.model.bom import Bom

from alma_sbom.data.models import Package, Build
from alma_sbom.config.config import CommonConfig, SbomFileFormatType
from ..document import Document as AlmasbomDocument

class CDXDocument(AlmasbomDocument):
    _bom: Bom

    def __init__(self):
        self._bom = None

    @classmethod
    def from_package(cls, package: Package, config: CommonConfig) -> "CDXDocument":
        doc = cls()
        return doc

    @classmethod
    def from_build(cls, build: Build, Commonconfig) -> "CDXDocument":
        doc = cls()
        return doc

    def write(self) -> None:
        raise NotImplementedError()

