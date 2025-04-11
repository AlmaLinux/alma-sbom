import argparse
from logging import getLogger
from typing import ClassVar, TYPE_CHECKING

from alma_sbom.cli.config import CommonConfig, PackageConfig

from .commands import SubCommand

### TODO:
##  We should avoid importing modules from outside the CLI layer except for TYPE_CHECKING
#if TYPE_CHECKING:
#    from alma_sbom.data import Package
from alma_sbom.data import Package, NullPackage

_logger = getLogger(__name__)

class PackageCommand(SubCommand):
    CONFIG_CLASS : ClassVar[type[CommonConfig]] = PackageConfig
    config: PackageConfig

    def run(self) -> int:
        package = self.runner()
        doc = self.document_factory.gen_from_package(package)
        doc.write(self.config.output_file)
        return 0

    def _select_runner(self) -> None:
        if self.config.rpm_package_hash:
            self.runner = self._runner_with_rpm_package_hash
        elif self.config.rpm_package:
            self.runner = self._runner_with_rpm_package
        else:
            raise RuntimeError(
                'Unexpected situation has occurred. '
                'Required info to generate SBOM of package has not been provided.'
            )

    def _runner_with_rpm_package_hash(self) -> 'Package':
        immudb_collector = self.collector_factory.gen_immudb_collector()
        try:
            return immudb_collector.collect_package_by_hash(self.config.rpm_package_hash)
        except KeyError as e:
            raise KeyError(f'Failed to get data from immudb for hash value: {self.config.rpm_package_hash}') from e

    def _runner_with_rpm_package(self) -> 'Package':
        immudb_collector = self.collector_factory.gen_immudb_collector()
        rpm_collector = self.collector_factory.gen_rpm_collector()

        try:
            pkg_from_immudb = immudb_collector.collect_package_by_package(self.config.rpm_package)
        except KeyError as e:
            _logger.warning(f'Failed to get data from immudb corresponding to {self.config.rpm_package}')
            _logger.warning(f'Create SBOM from only package data.')
            pkg_from_immudb = NullPackage
        pkg_from_pkg = rpm_collector.collect_package_from_file(self.config.rpm_package)

        pkg_merged = pkg_from_immudb.merge(pkg_from_pkg)
        return pkg_merged

