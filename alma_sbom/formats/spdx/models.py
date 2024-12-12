import datetime
from enum import Enum
from typing import Callable
from logging import getLogger
from spdx_tools.spdx.model import (
    CreationInfo,
    Document,
)
from spdx_tools.spdx.writer.json import json_writer
from spdx_tools.spdx.writer.tagvalue import tagvalue_writer
from spdx_tools.spdx.writer.xml import xml_writer
from spdx_tools.spdx.writer.yaml import yaml_writer

from alma_sbom.data.models import Package, Build
from alma_sbom.config.config import CommonConfig, SbomFileFormatType

_logger = getLogger(__name__)


class SPDXFormatter:
    FORMATTERS = {
        SbomFileFormatType.JSON: json_writer,
        SbomFileFormatType.TAGVALUE: tagvalue_writer,
        SbomFileFormatType.XML: xml_writer,
        SbomFileFormatType.YAML: yaml_writer,
    }
    formatter: Callable

    def __init__(self, file_format: SbomFileFormatType) -> None:
        self.formatter = self.FORMATTERS[file_format]

class SPDXDocument:
    document: Document
    config: CommonConfig
    formatter: SPDXFormatter

    def __init__(self, config: CommonConfig) -> None:
        ### TODO
        # This is test implementation
        # need to be fixed
        doc_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name='test implementation doc',
            #data_license=constants.ALMAOS_SBOMLICENSE,
            #document_namespace=f"{constants.ALMAOS_NAMESPACE}-{doc_name}-{doc_uuid}",
            document_namespace=f"testimple-testdoc",
            creators=[],
            created=datetime.datetime.now(),
        )
        self.document = Document(doc_info)
        self.config = config
        self.formatter = SPDXFormatter(self.config.sbom_type.file_format_type)

    def _make_each_package_component(package: Package):
        pass

    @classmethod
    def from_package(cls, package: Package, config: CommonConfig) -> "SPDXDocument":
        doc = cls(config)
        return doc

    @classmethod
    def from_build(cls, build: Build, config: CommonConfig) -> "SPDXDocument":
        doc = cls(config)
        return doc

    def write(self) -> None:
        self.formatter.formatter.write_document_to_file(
            self.document,
            self.config.output_file,
            validate=False,  ### need to be fixed to 'True'
        )

