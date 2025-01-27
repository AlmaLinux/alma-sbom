import argparse

from alma_sbom.cli.config import CommonConfig

from .commands import SubCommand
from .package import PackageCommand
from .build import BuildCommand

command_classes: dict[str, type[SubCommand]] = {
    'package': PackageCommand,
    'build': BuildCommand
}

def command_factory(base: CommonConfig, args: argparse.Namespace) -> SubCommand:
    try:
        command_class = command_classes[args.command]
        return command_class(base, args)
    except KeyError:
        raise ValueError(f"Unknown command: {args.command}")

def setup_subparsers(subparsers: argparse._SubParsersAction) -> None:
    for name, command_class in command_classes.items():
        command_class.add_arguments(subparsers)

