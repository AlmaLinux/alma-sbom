import unittest
from alma_sbom.formats.cyclonedx.models import CDXDocument

class TestSPDXDocument(unittest.TestCase):
    def test_constructor(self):
        spdx_doc = CDXDocument()

