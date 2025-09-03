import unittest
from alma_sbom.formats.spdx.document import SPDXDocument
from alma_sbom.cli.config import CommonConfig

class TestSPDXDocument(unittest.TestCase):
    def test_constructor(self):
        ### Now use default
        spdx_doc = SPDXDocument(CommonConfig.DEF_SBOM_TYPE.file_format_type, 'test_doc')

