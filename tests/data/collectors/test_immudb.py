import unittest

from alma_sbom.data.collectors import ImmudbCollector
from alma_sbom.cli.config import CommonConfig

class TestCollector(unittest.TestCase):
    def test_constructor(self):
        collector = ImmudbCollector(
            ### Now use default
            username=CommonConfig.DEF_IMMUDB_USERNAME,
            password=CommonConfig.DEF_IMMUDB_PASSWORD,
            database=CommonConfig.DEF_IMMUDB_DATABASE,
            immudb_address=CommonConfig.DEF_IMMUDB_ADDRESS,
            public_key_file=CommonConfig.DEF_IMMUDB_PUBLIC_KEY_FILE,
        )
