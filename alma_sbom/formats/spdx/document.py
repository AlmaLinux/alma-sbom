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
from spdx_tools.spdx.writer.rdf import rdf_writer

from alma_sbom.type import SbomFileFormatType
from alma_sbom.data.models import Package, Build, Iso
from alma_sbom.formats.document import Document as AlmasbomDocument

from . import constants as spdx_consts
from .component import set_package_component, set_build_component, set_iso_component

_logger = getLogger(__name__)


class SPDXFormatter:
    FORMATTERS = {
        SbomFileFormatType.JSON: json_writer,
        SbomFileFormatType.TAGVALUE: tagvalue_writer,
        SbomFileFormatType.XML: xml_writer,
        SbomFileFormatType.YAML: yaml_writer,
        SbomFileFormatType.RDF: rdf_writer,
    }
    formatter: Callable

    def __init__(self, file_format: SbomFileFormatType) -> None:
        self.formatter = self.FORMATTERS[file_format]

class SPDXDocument(AlmasbomDocument):
    document: Document
    formatter: SPDXFormatter
    doc_name: str
    doc_uuid: str
    _next_id: int = 0

    def __init__(self, file_format_type: SbomFileFormatType, doc_name: str) -> None:
        ### TODO
        # This is test implementation
        # need to be fixed
        self.doc_name = doc_name
        self.doc_uuid = uuid.uuid4()
        doc_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name=doc_name,
            data_license=spdx_consts.ALMAOS_SBOMLICENSE,
            document_namespace=self._get_document_namespace(),
            creators=spdx_consts.CREATORS,
            created=datetime.now(),
        )
        self.document = Document(doc_info)
        self.formatter = SPDXFormatter(file_format_type)
        self._next_id = 0

    @classmethod
    def from_package(cls, package: Package, file_format_type: SbomFileFormatType) -> "SPDXDocument":
        doc_name = package.get_doc_name()
        doc = cls(file_format_type, doc_name)
        doc._add_each_package_component(package)
        return doc

    @classmethod
    def from_build(cls, build: Build, file_format_type: SbomFileFormatType) -> "SPDXDocument":
        doc_name = build.get_doc_name()
        doc = cls(file_format_type, doc_name)

        set_build_component(doc.document, build, doc.document.creation_info.spdx_id)

        for pkg in build.packages:
            doc._add_each_package_component(pkg)

        return doc

    @classmethod
    def from_iso(cls, iso: Iso, file_format_type: SbomFileFormatType) -> "SPDXDocument":
        doc_name = iso.get_doc_name()
        doc = cls(file_format_type, doc_name)

        set_iso_component(doc.document, iso, doc.document.creation_info.spdx_id)

        for pkg in iso.packages:
            doc._add_each_package_component(pkg)

        return doc

    def write(self, output_file: str) -> None:
        self.formatter.formatter.write_document_to_file(
            self.document,
            output_file,
            validate=True,
        )

    def _get_document_namespace(self) -> str:
        return f"{spdx_consts.SPDX_ALMAOS_NAMESPACE}-{self.doc_name}-{self.doc_uuid}"

    def _get_next_package_id(self) -> str:
        """Return an identifier that can be assigned to a package in this document.

        Further reading:
        https://spdx.github.io/spdx-spec/v2-draft/package-information/#72-package-spdx-identifier-field
        """
        cur_id = self._next_id
        self._next_id += 1
        return f"SPDXRef-{cur_id}"

    def _add_each_package_component(self, package: Package) -> None:
        set_package_component(self.document, package, self._get_next_package_id())

