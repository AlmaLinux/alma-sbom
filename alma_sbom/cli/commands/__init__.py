import argparse

from .commands import SubCommand
from .package import PackageCommand
from .build import BuildCommand


command_classes: dict[str, type[SubCommand]] = {
    'package': PackageCommand,
    'build': BuildCommand
}

def command_factory(command_name: str) -> SubCommand:
    try:
        command_class = command_classes[command_name]
        return command_class()
    except KeyError:
        raise ValueError(f"Unknown command: {command_name}")

def setup_subparsers(subparsers: argparse._SubParsersAction) -> None:
    for name, command_class in command_classes.items():
        #subparser = subparsers.add_parser(name)
        #command_class().add_arguments(subparser)
        command_class().add_arguments(subparsers)
