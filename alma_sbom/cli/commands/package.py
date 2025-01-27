import argparse
from logging import getLogger
from typing import Callable

from alma_sbom.data import Package, ImmudbCollector
from alma_sbom.formats import Document, document_factory
from .commands import SubCommand
from ..config.config import CommonConfig
from ..config.models.package import PackageConfig

from alma_sbom.cli.factory.collectors.factory import CollectorFactory

_logger = getLogger(__name__)

class PackageCommand(SubCommand):
    config: PackageConfig
    collector_factory: CollectorFactory
    doc: Document
    runner: Callable

    def __init__(self, base: CommonConfig, args: argparse.Namespace) -> None:
        self.config = PackageConfig.from_base_args(base, args)
        self.collector_factory = CollectorFactory(self.config)
        self._select_runner()

    def run(self) -> int:
        package = self.runner()

        document_class = document_factory(self.config.sbom_type.record_type)
        self.doc = document_class.from_package(package, self.config.sbom_type.file_format_type)
        self.doc.write(self.config.output_file)

        return 0

    def _select_runner(self) -> None:
        if self.config.rpm_package_hash:
            self.runner = self._runner_with_rpm_package_hash
        elif self.config.rpm_package:
            self.runner = self._runner_with_rpm_package
        else:
            raise RuntimeError('Unexpected situation has occurred')

    def _runner_with_rpm_package_hash(self) -> Package:
        immudb_collector = self.collector_factory.gen_immudb_collector()
        return immudb_collector.collect_package_by_hash(self.config.rpm_package_hash)

    def _runner_with_rpm_package(self) -> Package:
        raise NotImplementedError()

