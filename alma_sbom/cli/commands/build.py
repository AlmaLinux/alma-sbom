import argparse
from logging import getLogger
from typing import Callable

from alma_sbom.data import Build, ImmudbCollector, AlbsCollector
from alma_sbom.formats import Document, document_factory
from .commands import SubCommand
from ..config.config import CommonConfig
from ..config.models.build import BuildConfig

from alma_sbom.cli.factory.collectors.factory import CollectorFactory

_logger = getLogger(__name__)

class BuildCommand(SubCommand):
    config: BuildConfig
    collector_factory: CollectorFactory
    doc: Document
    collector_runner: Callable

    def __init__(self, base: CommonConfig, args: argparse.Namespace) -> None:
        self.config = self._get_BuildConfig_from_args(base, args)
        self.collector_factory = CollectorFactory(self.config)
        self._select_runner()

    @staticmethod
    def add_arguments(parser: argparse._SubParsersAction) -> None:
        build_parser = parser.add_parser('build', help='Generate build SBOM')
        build_parser.add_argument(
            '--build-id',
            type=str,
            help='SHA256 hash of an RPM package',
            required=True,
        )

    def run(self) -> int:
        build = self.collector_runner()
        document_class = document_factory(self.config.sbom_type.record_type)
        self.doc = document_class.from_build(build, self.config.sbom_type.file_format_type)
        self.doc.write(self.config.output_file)
        return 0

    @staticmethod
    def _get_BuildConfig_from_args(base: CommonConfig, args: argparse.Namespace) -> BuildConfig:
        return BuildConfig.from_base(base, build_id=args.build_id)

    def _select_runner(self) -> None:
        if self.config.build_id:
            self.collector_runner = self._runner_with_build_id
        else:
            raise RuntimeError('Unexpected situation has occurred')

    def _runner_with_build_id(self) -> Build:
        albs_collector = AlbsCollector()
        build, package_hash_list = albs_collector.collect_build_by_id(build_id=self.config.build_id)

        immudb_collector = self.collector_factory.gen_immudb_collector()
        for hash in package_hash_list:
            pkg_comp = immudb_collector.collect_package_by_hash(hash)
            build.append_package(pkg_comp)

        return build

