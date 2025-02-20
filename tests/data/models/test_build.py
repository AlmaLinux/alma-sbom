import unittest
from alma_sbom.data.models import Package, Build

class TestPackage(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_constructor(self):
        p = Package()
        b = Build(build_id=1111, author='test author', packages=[p])

