import argparse
import sys

from .commands import SubCommand, setup_subparsers

class Main:
    command: SubCommand

    def __init__(self):
        pass

    def run(self, args: list[str]) -> int:
        #config = self.config_parser.parse(args)
        parser = create_parser()
        parsed_args = parser.parse_args(args)
        return 0


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='alma-sbom')

    ### outpout related settings ###
    parser.add_argument(
        '--output-file',
        type=str,
        help=(
            'Full path to an output file with SBOM. Output will be '
            'to stdout if the parameter is absent or emtpy'
        ),
        required=False,
        default=None,
    )

    ### subcommand settings ###
    subparsers = parser.add_subparsers(dest='command', required=True)
    print(f'type(subparsers): {type(subparsers)}')
    setup_subparsers(subparsers)

    # #### package subcommand ####
    # package_parser = subparsers.add_parser('package', help='Generate package SBOM')
    # object_id_group = package_parser.add_mutually_exclusive_group(required=True)
    # object_id_group.add_argument(
    #     '--rpm-package-hash',
    #     type=str,
    #     help='SHA256 hash of an RPM package',
    # )
    # object_id_group.add_argument(
    #     '--rpm-package',
    #     type=str,
    #     help='path to an RPM package',
    # )
    # package_parser.set_defaults(func=package.execute)


    # #### build subcommand ####
    # build_parser = subparsers.add_parser('build', help='Generate build SBOM')
    # build_parser.add_argument(
    #     '--build-id',
    #     type=int,
    #     help='UID of a build from AlmaLinux Build System',
    # )
    # build_parser.set_defaults(func=build.execute)

    return parser

def cli_main():
    args = sys.argv[1:]
    _main = Main()
    return _main.run(args)
