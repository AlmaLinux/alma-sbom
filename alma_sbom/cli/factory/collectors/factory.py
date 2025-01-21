from alma_sbom.cli.config import CommonConfig
from alma_sbom.data import (
    ImmudbCollector,
    AlbsCollector,
    RpmCollector,
)

class CollectorFactory:
    config: CommonConfig

    def __init__(self, config: CommonConfig):
        self.config = config

    def gen_immudb_collector(self) -> ImmudbCollector:
        return ImmudbCollector(
             username=self.config.immudb_username,
             password=self.config.immudb_password,
             database=self.config.immudb_database,
             immudb_address=self.config.immudb_address,
             public_key_file=self.config.immudb_public_key_file,
        )

    def gen_albs_collector(self) -> AlbsCollector:
        raise NotImplementedError()

    def gen_rpm_collector(self) -> RpmCollector:
        raise NotImplementedError()

