import argparse
from logging import getLogger
from typing import ClassVar, TYPE_CHECKING

from alma_sbom.cli.config import CommonConfig, BuildConfig

from .commands import SubCommand

if TYPE_CHECKING:
    from alma_sbom.data import Build

_logger = getLogger(__name__)

class BuildCommand(SubCommand):
    CONFIG_CLASS : ClassVar[type[CommonConfig]] = BuildConfig
    config: BuildConfig

    def run(self) -> int:
        build = self.runner()
        doc = self.document_factory.gen_from_build(build)
        doc.write(self.config.output_file)
        return 0

    def _select_runner(self) -> None:
        if self.config.build_id:
            self.runner = self._runner_with_build_id
        else:
            raise RuntimeError(
                'Unexpected situation has occurred. '
                'Required info to generate SBOM of build has not been provided.'
            )

    def _runner_with_build_id(self) -> 'Build':
        albs_collector = self.collector_factory.gen_albs_collector()
        build, package_hash_list = albs_collector.collect_build_by_id(build_id=self.config.build_id)

        immudb_collector = self.collector_factory.gen_immudb_collector()
        for hash in package_hash_list:
            pkg_comp = immudb_collector.collect_package_by_hash(hash)
            build.append_package(pkg_comp)

        return build

