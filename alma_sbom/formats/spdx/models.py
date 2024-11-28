from enum import Enum
from spdx_tools.spdx.model import (
    Document,
)

from alma_sbom.data.models import Package, Build

class SPDXFormat(Enum):
    JSON = "json"
    XML = "xml"
    YAML = "yaml"

class SPDXDocument:
    document: Document

    def __init__(self):
        self.document = None

    @classmethod
    def from_package(cls, package: Package) -> "SPDXDocument":
        doc = cls()
        return doc

    @classmethod
    def from_package(cls, build: Build) -> "SPDXDocument":
        doc = cls()
        return doc

    def write(self, output_file: str, format: SPDXFormat) -> None:
        pass

