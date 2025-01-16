from typing import Callable

from alma_sbom.data import Package
from alma_sbom.data.collectors import ImmudbCollector

from alma_sbom.config.models.package import PackageConfig
from .runner import CollectorRunner

class PackageCollectorRunner(CollectorRunner):
    config: PackageConfig
    func: Callable

    def __init__(self, config: PackageConfig):
        super().__init__(config)
        self._selector()

    def _selector(self) -> None:
        if self.config.rpm_package_hash:
            self.func = self._from_rpm_package_hash
        elif self.config.rpm_package:
            self.func = self._from_rpm_package
        else:
            raise RuntimeError('Unexpected situation has occurred')

    def run(self) -> Package:
        return self.func()

    def _from_rpm_package_hash(self) -> Package:
        immudb_collector = ImmudbCollector()
        return immudb_collector.collect_package_by_hash(self.config.rpm_package_hash)

    def _from_rpm_package(self) -> Package:
        raise NotImplementedError()

