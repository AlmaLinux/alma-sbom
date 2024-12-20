from enum import Enum
from typing import Callable
from logging import getLogger

from cyclonedx.model.bom import Bom
from cyclonedx.output import BaseOutput
from cyclonedx.output.json import JsonV1Dot4
from cyclonedx.output.xml import XmlV1Dot4

from alma_sbom.data.models import Package, Build
from alma_sbom.config.config import CommonConfig, SbomFileFormatType
from ..document import Document as AlmasbomDocument
from .component import component_from_package

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
    config: CommonConfig
    formatter: CDXFormatter

    def __init__(self, config: CommonConfig):
        self.bom = Bom()
        #self.bom.metadata.tools.components.add(cdx_lib_component())
        self.config = config
        self.formatter = CDXFormatter(self.config.sbom_type.file_format_type)

    @classmethod
    def from_package(cls, package: Package, config: CommonConfig) -> "CDXDocument":
        doc = cls(config)
        doc.bom.metadata.component = component_from_package(package)
        return doc

    @classmethod
    def from_build(cls, build: Build, Commonconfig) -> "CDXDocument":
        doc = cls(config)
        return doc

    ###TODO:
    # need to be rewriten after library update.
    def write(self) -> None:
        pretty_output = self.formatter.writer(self.bom)
        with open(self.config.output_file, 'w') as fd:
            fd.write(pretty_output)

