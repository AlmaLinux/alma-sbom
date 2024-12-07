import argparse

from .commands import SubCommand
from ...config.models.build import BuildConfig

class BuildCommand(SubCommand):
    config: BuildConfig

    def __init__(self, args: argparse.Namespace) -> None:
        self.config = self._get_BuildConfig_from_args(args)

    @staticmethod
    def add_arguments(parser: argparse._SubParsersAction) -> None:
        build_parser = parser.add_parser('build', help='Generate build SBOM')
        build_parser.add_argument(
            '--build-id',
            type=str,
            help='SHA256 hash of an RPM package',
            required=True,
        )

    def execute(self, args: argparse.Namespace) -> None:
        pass

    @staticmethod
    def _get_BuildConfig_from_args(args: argparse.Namespace) -> BuildConfig:
        return BuildConfig(
            output_file=args.output_file,
            build_id=args.build_id,
        )

