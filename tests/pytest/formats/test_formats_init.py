from alma_sbom.type import SbomRecordType
from alma_sbom.formats import document_factory
from alma_sbom.formats.spdx.document import SPDXDocument
from alma_sbom.formats.cyclonedx.document import CDXDocument

def test_document_factory() -> None:
    assert document_factory(SbomRecordType.SPDX) == SPDXDocument
    assert document_factory(SbomRecordType.CYCLONEDX) == CDXDocument

