import argparse
from logging import getLogger
from typing import Callable

from alma_sbom.data import Package, ImmudbCollector
from alma_sbom.formats import Document, document_factory
from .commands import SubCommand
from ..config.config import CommonConfig
from ..config.models.package import PackageConfig

_logger = getLogger(__name__)

class PackageCommand(SubCommand):
    config: PackageConfig
    doc: Document
    collector_runner: Callable

    def __init__(self, base: CommonConfig, args: argparse.Namespace) -> None:
        self.config = self._get_PackageConfig_from_args(base, args)
        self._select_runner()

    @staticmethod
    def add_arguments(parser: argparse._SubParsersAction) -> None:
        package_parser = parser.add_parser('package', help='Generate package SBOM')
        object_id_group = package_parser.add_mutually_exclusive_group(required=True)
        object_id_group.add_argument(
            '--rpm-package-hash',
            type=str,
            help='SHA256 hash of an RPM package',
        )
        object_id_group.add_argument(
            '--rpm-package',
            type=str,
            help='path to an RPM package',
        )

    def run(self) -> int:
        package = self.collector_runner()

        document_class = document_factory(self.config.sbom_type.record_type)
        self.doc = document_class.from_package(package, self.config.sbom_type.file_format_type)
        self.doc.write(self.config.output_file)

        return 0

    @staticmethod
    def _get_PackageConfig_from_args(base: CommonConfig, args: argparse.Namespace) -> PackageConfig:
        return PackageConfig.from_base(base, args.rpm_package_hash, args.rpm_package)

    def _select_runner(self) -> None:
        if self.config.rpm_package_hash:
            self.collector_runner = self._runner_with_rpm_package_hash
        elif self.config.rpm_package:
            self.collector_runner = self._runner_with_rpm_package
        else:
            raise RuntimeError('Unexpected situation has occurred')

    def _runner_with_rpm_package_hash(self) -> Package:
        immudb_collector = ImmudbCollector()
        return immudb_collector.collect_package_by_hash(self.config.rpm_package_hash)

    def _runner_with_rpm_package(self) -> Package:
        raise NotImplementedError()

