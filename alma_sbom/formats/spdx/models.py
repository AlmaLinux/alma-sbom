import uuid
from datetime import datetime
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

from alma_sbom import constants
from alma_sbom.data.models import Package, Build
from alma_sbom.config.config import CommonConfig, SbomFileFormatType
from ..document import Document as AlmasbomDocument
from .component import component_from_package

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

class SPDXDocument(AlmasbomDocument):
    SPDX_ALMAOS_NAMESPACE = constants.ALMAOS_NAMESPACE + '/spdx'

    document: Document
    config: CommonConfig
    formatter: SPDXFormatter
    doc_uuid: str
    _next_id: int = 0

    def __init__(self, config: CommonConfig, doc_name: str) -> None:
        ### TODO
        # This is test implementation
        # need to be fixed
        self.doc_uuid = uuid.uuid4()
        doc_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name=doc_name,
            data_license=constants.ALMAOS_SBOMLICENSE,
            document_namespace=f"{SPDXDocument.SPDX_ALMAOS_NAMESPACE}-{doc_name}-{self.doc_uuid}",
            creators=[],
            created=datetime.now(),
        )
        self.document = Document(doc_info)
        self.config = config
        self.formatter = SPDXFormatter(self.config.sbom_type.file_format_type)
        self._next_id = 0

    @classmethod
    def from_package(cls, package: Package, config: CommonConfig) -> "SPDXDocument":
        doc_name = package.get_doc_name()
        doc = cls(config, doc_name)

        doc._add_each_package_component(package)

        return doc

    @classmethod
    def from_build(cls, build: Build, config: CommonConfig) -> "SPDXDocument":
        doc_name = 'testtesttest doc_name'
        doc = cls(config, doc_name)
        return doc

    def write(self) -> None:
        self.formatter.formatter.write_document_to_file(
            self.document,
            self.config.output_file,
            validate=False,  ### need to be fixed to 'True'
        )

    def get_next_package_id(self) -> str:
        """Return an identifier that can be assigned to a package in this document.

        Further reading:
        https://spdx.github.io/spdx-spec/v2-draft/package-information/#72-package-spdx-identifier-field
        """
        cur_id = self._next_id
        self._next_id += 1
        return f"SPDXRef-{cur_id}"

    def _add_each_package_component(self, package: Package) -> None:
        pkg, rel = component_from_package(package, self.get_next_package_id())
        self.document.packages += [pkg]
        self.document.relationships += [rel]

