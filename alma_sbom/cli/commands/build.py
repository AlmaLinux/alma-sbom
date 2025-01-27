import argparse
from logging import getLogger
from typing import Callable, TYPE_CHECKING

from alma_sbom.cli.config import CommonConfig, BuildConfig
from alma_sbom.cli.factory import CollectorFactory, DocumentFactory

from .commands import SubCommand

if TYPE_CHECKING:
    from alma_sbom.data import Build

_logger = getLogger(__name__)

class BuildCommand(SubCommand):
    config: BuildConfig
    collector_factory: CollectorFactory
    document_factory: DocumentFactory
    runner: Callable

    def __init__(self, base: CommonConfig, args: argparse.Namespace) -> None:
        self.config = BuildConfig.from_base_args(base, args)
        self.collector_factory = CollectorFactory(self.config)
        self.document_factory = DocumentFactory(self.config)
        self._select_runner()

    def run(self) -> int:
        build = self.runner()
        doc = self.document_factory.gen_from_build(build)
        doc.write(self.config.output_file)
        return 0

    def _select_runner(self) -> None:
        if self.config.build_id:
            self.runner = self._runner_with_build_id
        else:
            raise RuntimeError('Unexpected situation has occurred')

    def _runner_with_build_id(self) -> 'Build':
        albs_collector = self.collector_factory.gen_albs_collector()
        build, package_hash_list = albs_collector.collect_build_by_id(build_id=self.config.build_id)

        immudb_collector = self.collector_factory.gen_immudb_collector()
        for hash in package_hash_list:
            pkg_comp = immudb_collector.collect_package_by_hash(hash)
            build.append_package(pkg_comp)

        return build

