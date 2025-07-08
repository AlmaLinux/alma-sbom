import unittest

from alma_sbom.data.collectors import RpmCollector

class TestCollector(unittest.TestCase):
    def test_constructor(self):
        collector = RpmCollector
