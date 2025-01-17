from enum import Enum
from typing import Callable
from logging import getLogger

from cyclonedx.model.bom import Bom, Tool
from cyclonedx.output import BaseOutput
from cyclonedx.output.json import JsonV1Dot4
from cyclonedx.output.xml import XmlV1Dot4

from alma_sbom import constants
from alma_sbom.data.models import Package, Build
from alma_sbom.type import SbomFileFormatType
from ..document import Document as AlmasbomDocument
from .component import component_from_package, component_from_build

_logger = getLogger(__name__)


class CDXFormatter:
    FORMATTERS = {
        SbomFileFormatType.JSON: JsonV1Dot4,
        SbomFileFormatType.XML: XmlV1Dot4,
    }
    formatter: BaseOutput

    ### TODO:
    # Current writer in cyclonedx-python-libs(==2.7.1) doesn't have indent and pretty option.
    # So, we need to implement writer using basic library.
    # The newer cyclonedx-python-libs has that. These are likely rewirte after library update.
    WRITERS = {
        SbomFileFormatType.JSON: '_write_json',
        SbomFileFormatType.XML: '_write_xml',
    }
    writer: Callable

    def __init__(self, file_format: SbomFileFormatType) -> None:
        self.formatter = self.FORMATTERS[file_format]
        self.writer = getattr(self, self.WRITERS[file_format])

    ###TODO:
    # writer functions are likely renmove after library update.
    def _write_json(self, bom: Bom) -> str:
        import json
        formatter = self.formatter(bom)
        output_str = formatter.output_as_string()
        json_output = json.loads(output_str)
        return json.dumps(json_output, indent=4)

    def _write_xml(self, bom: Bom) -> str:
        import xml.dom.minidom
        formatter = self.formatter(bom)
        output_str = formatter.output_as_string()
        xml_output = xml.dom.minidom.parseString(output_str)
        return xml_output.toprettyxml()

class CDXDocument(AlmasbomDocument):
    bom: Bom
    formatter: CDXFormatter

    def __init__(self, file_format_type: SbomFileFormatType):
        self.bom = Bom()

        ### TODO:
        # These tool components, being specific to alma-sbom rather than part of the format,
        # should perhaps be managed within each data class under data/models.
        for tool in constants.TOOLS:
            self.bom.metadata.tools.add(Tool(
                vendor=tool['vendor'],
                name=tool['name'],
                version=tool['version'],
            ))
        #self.bom.metadata.tools.components.add(cdx_lib_component())

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

    ###TODO:
    # need to be rewriten after library update.
    def write(self, output_file: str) -> None:
        pretty_output = self.formatter.writer(self.bom)
        with open(output_file, 'w') as fd:
            fd.write(pretty_output)

