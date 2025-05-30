
from alma_sbom.type import SbomRecordType
from .document import Document
from .spdx.document import SPDXDocument
from .cyclonedx.document import CDXDocument

document_classes: dict[SbomRecordType, type[Document]] = {
    SbomRecordType.SPDX: SPDXDocument,
    SbomRecordType.CYCLONEDX: CDXDocument,
}

def document_factory(format: SbomRecordType) -> type[Document]:
    return document_classes.get(format)

