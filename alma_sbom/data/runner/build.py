from typing import Callable

from alma_sbom.data import Build
from alma_sbom.data.collectors import ImmudbCollector, AlbsCollector
from alma_sbom.config.models.build import BuildConfig
from .runner import CollectorRunner

class BuildCollectorRunner(CollectorRunner):
    config: BuildConfig
    func: Callable

    def __init__(self, config: BuildConfig):
        super().__init__(config)
        self._selector()

    def _selector(self) -> None:
        if self.config.build_id:
            self.func = self._from_build_id
        else:
            raise RuntimeError('Unexpected situation has occurred')

    def run(self) -> Build:
        return self.func()

    def _from_build_id(self) -> Build:
        albs_collector = AlbsCollector()
        build, package_hash_list = albs_collector.collect_build_by_id(build_id=self.config.build_id)

        immudb_collector = ImmudbCollector()
        for hash in package_hash_list:
            pkg_comp = immudb_collector.collect_package_by_hash(hash)
            build.append_package(pkg_comp)

        return build

