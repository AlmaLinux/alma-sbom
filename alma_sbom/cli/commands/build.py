import argparse

from .commands import SubCommand

class BuildCommand(SubCommand):
    def add_arguments(self, parser: argparse._SubParsersAction) -> None:
        build_parser = parser.add_parser('build', help='Generate build SBOM')
        build_parser.add_argument(
            '--build-id',
            type=str,
            help='SHA256 hash of an RPM package',
        )

    def execute(self, args: argparse.Namespace) -> None:
        pass
