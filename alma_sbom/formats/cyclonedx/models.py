from enum import Enum
from cyclonedx.model.bom import Bom

from alma_sbom.data.models import Package, Build

class CDXFormat(Enum):
    JSON = "json"
    XML = "xml"

class CDXDocument:
    _bom: Bom

    def __init__(self):
        self._bom = None

    @classmethod
    def from_package(cls, package: Package) -> "CDXDocument":
        doc = cls()
        return doc

    @classmethod
    def from_package(cls, build: Build) -> "CDXDocument":
        doc = cls()
        return doc

    def write(self, output_file: str, format: CDXFormat):
        pass
