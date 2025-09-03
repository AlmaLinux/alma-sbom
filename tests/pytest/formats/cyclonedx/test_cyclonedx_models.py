import unittest
from alma_sbom.formats.cyclonedx.document import CDXDocument
from alma_sbom.cli.config import CommonConfig

class TestSPDXDocument(unittest.TestCase):
    def test_constructor(self):
        spdx_doc = CDXDocument(CommonConfig.DEF_SBOM_TYPE.file_format_type)

