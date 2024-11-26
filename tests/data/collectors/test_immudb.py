import unittest

from alma_sbom.data.collectors import ImmudbCollector

class TestCollector(unittest.TestCase):
    def test_constructor(self):
        collector = ImmudbCollector()
