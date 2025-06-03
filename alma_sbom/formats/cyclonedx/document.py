from enum import Enum
from typing import TYPE_CHECKING
from logging import getLogger

from cyclonedx.builder.this import this_component as cdx_lib_component
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion

if TYPE_CHECKING:
    from cyclonedx.output import BaseOutput

from alma_sbom import constants
from alma_sbom.data.models import Package, Build, Iso
from alma_sbom.type import SbomFileFormatType
from alma_sbom.formats.document import Document as AlmasbomDocument

from .component import component_from_package, component_from_build, component_from_iso

_logger = getLogger(__name__)


class CDXFormatter:
    FORMATS_MAP = {
        SbomFileFormatType.JSON: OutputFormat.JSON,
        SbomFileFormatType.XML: OutputFormat.XML,
    }
    SCHEMA_VERSION: SchemaVersion = SchemaVersion.V1_6

    output_format_type: OutputFormat

    def __init__(self, file_format: SbomFileFormatType) -> None:
        self.output_format_type = self.FORMATS_MAP[file_format]

    def write(self, bom: Bom) -> str:
        outputter: BaseOutput = make_outputter(
            bom,
            self.output_format_type,
            self.SCHEMA_VERSION,
        )
        output = outputter.output_as_string(indent=4)
        return output

class CDXDocument(AlmasbomDocument):
    bom: Bom
    formatter: CDXFormatter

    def __init__(self, file_format_type: SbomFileFormatType):
        self.bom = Bom()

        for tool in constants.TOOLS:
            self.bom.metadata.tools.components.add(Component(
                name=tool['name'],
                ### NOTE:
                # Use group attribute as vendor
                group=tool['vendor'],
                version=tool['version'],
                type=None,
            ))
        self.bom.metadata.tools.components.add(cdx_lib_component())

        self.formatter = CDXFormatter(file_format_type)

    @classmethod
    def from_package(cls, package: Package, file_format_type: SbomFileFormatType) -> "CDXDocument":
        doc = cls(file_format_type)
        doc.bom.metadata.component = component_from_package(package)
        return doc

    @classmethod
    def from_build(cls, build: Build, file_format_type: SbomFileFormatType) -> "CDXDocument":
        doc = cls(file_format_type)

        doc.bom.metadata.component = component_from_build(build)
        for pkg in build.packages:
            doc.bom.components.add(component_from_package(pkg))

        return doc

    @classmethod
    def from_iso(cls, iso: Iso, file_format_type: SbomFileFormatType) -> "CDXDocument":
        doc = cls(file_format_type)

        doc.bom.metadata.component = component_from_iso(iso)
        for pkg in iso.packages:
            doc.bom.components.add(component_from_package(pkg))

        return doc

    def write(self, output_file: str) -> None:
        pretty_output = self.formatter.write(self.bom)
        with open(output_file, 'w') as fd:
            fd.write(pretty_output)

