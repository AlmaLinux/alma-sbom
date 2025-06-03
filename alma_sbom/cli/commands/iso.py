import argparse
import tempfile
from logging import getLogger
from typing import ClassVar, TYPE_CHECKING

from alma_sbom.cli.config import CommonConfig, IsoConfig

### TODO: https://github.com/AlmaLinux/alma-sbom/issues/59
from alma_sbom.data import NullPackage

from .commands import SubCommand

_logger = getLogger(__name__)

class IsoCommand(SubCommand):
    CONFIG_CLASS : ClassVar[type[CommonConfig]] = IsoConfig
    config: IsoConfig

    def run(self) -> int:
        iso = self.runner()
        doc = self.document_factory.gen_from_iso(iso)
        doc.write(self.config.output_file)
        return 0

    def _select_runner(self) -> None:
        if self.config.iso_image:
            self.runner = self._runner_with_iso_image
        else:
            raise RuntimeError('Unexpected situation has occurred')

    def _runner_with_iso_image(self) -> 'Iso':
        iso_collector = self.collector_factory.gen_iso_collector()
        immudb_collector = self.collector_factory.gen_immudb_collector()
        rpm_collector = self.collector_factory.gen_rpm_collector()

        iso = iso_collector.collect_iso_by_file(self.config.iso_image)

        count = 1
        fd_path = iso_collector.get_fd_path()
        for _ in iso_collector.iter_packages():
            _logger.debug(f'Processing package #{count}...')
            count = count + 1
            try:
                pkg_from_immudb = immudb_collector.collect_package_by_package(fd_path)
            except KeyError as e:
                pkg_from_immudb = NullPackage
            pkg_from_pkg = rpm_collector.collect_package_from_file(fd_path)
            pkg_merged = pkg_from_immudb.merge(pkg_from_pkg)
            iso.append_package(pkg_merged)

        return iso

