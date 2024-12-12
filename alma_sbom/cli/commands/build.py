import argparse
from logging import getLogger

from .commands import SubCommand
from ...config.config import CommonConfig
from ...config.models.build import BuildConfig

_logger = getLogger(__name__)

class BuildCommand(SubCommand):
    config: BuildConfig

    def __init__(self, base: CommonConfig, args: argparse.Namespace) -> None:
        self.config = self._get_BuildConfig_from_args(base, args)

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
        return 0

    @staticmethod
    def _get_BuildConfig_from_args(base: CommonConfig, args: argparse.Namespace) -> BuildConfig:
        return BuildConfig.from_base(base, build_id=args.build_id)

