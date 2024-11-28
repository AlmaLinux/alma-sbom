import unittest
from alma_sbom.formats.spdx.models import SPDXDocument

class TestSPDXDocument(unittest.TestCase):
    def test_constructor(self):
        spdx_doc = SPDXDocument()

