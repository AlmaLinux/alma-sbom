import argparse
from logging import getLogger

from .commands import SubCommand
from ...config.models.package import PackageConfig

_logger = getLogger(__name__)

class PackageCommand(SubCommand):
    config: PackageConfig

    def __init__(self, args: argparse.Namespace) -> None:
        _logger.debug('PackageCommand.__init__')
        self.config = self._get_PackageConfig_from_args(args)

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
        _logger.debug('PackageCommand.run')
        return 0

    @staticmethod
    def _get_PackageConfig_from_args(args: argparse.Namespace) -> PackageConfig:
        return PackageConfig(
            output_file=args.output_file,
            rpm_package_hash=args.rpm_package_hash,
            rpm_package=args.rpm_package,
        )

