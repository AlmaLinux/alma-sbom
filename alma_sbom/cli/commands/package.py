import argparse
from logging import getLogger

from .commands import SubCommand
from alma_sbom.data import DataCollector, data_collector_factory
from alma_sbom.config.config import CommonConfig
from alma_sbom.config.models.package import PackageConfig
from alma_sbom.formats.document import Document
from alma_sbom.formats import document_factory

_logger = getLogger(__name__)

class PackageCommand(SubCommand):
    config: PackageConfig
    doc: Document
    collector: DataCollector

    def __init__(self, base: CommonConfig, args: argparse.Namespace) -> None:
        self.config = self._get_PackageConfig_from_args(base, args)
        self.collector = data_collector_factory(self.config)

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
        package = self.collector.run()

        document_class = document_factory(self.config.sbom_type.record_type)
        self.doc = document_class.from_package(package, self.config)
        self.doc.write()

        return 0

    @staticmethod
    def _get_PackageConfig_from_args(base: CommonConfig, args: argparse.Namespace) -> PackageConfig:
        return PackageConfig.from_base(base, args.rpm_package_hash, args.rpm_package)

