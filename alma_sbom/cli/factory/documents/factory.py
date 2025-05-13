from typing import Any

from alma_sbom.cli.config import CommonConfig
from alma_sbom.formats import (
    document_factory,
    Document,
)

class DocumentFactory:
    config: CommonConfig
    document_class: type[Document]

    def __init__(self, config: CommonConfig):
        self.config = config
        self.document_class = document_factory(self.config.sbom_type.record_type)

    def gen_from_package(self, package: Any) -> Document:
        return self.document_class.from_package(package, self.config.sbom_type.file_format_type)

    def gen_from_build(self, build: Any) -> Document:
        return self.document_class.from_build(build, self.config.sbom_type.file_format_type)

    def gen_from_iso(self, iso: Any) -> Document:
        return self.document_class.from_iso(iso, self.config.sbom_type.file_format_type)

