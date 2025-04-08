import argparse

from alma_sbom.cli.config import CommonConfig

from .package import PackageConfig
from .build import BuildConfig
from .iso import IsoConfig

subconfig_classes: dict[str, type[CommonConfig]] = {
    'package': PackageConfig,
    'build': BuildConfig,
    'iso': IsoConfig,
}

def setup_subparsers(subparsers: argparse._SubParsersAction) -> None:
    for name, subconfig_class in subconfig_classes.items():
        subconfig_class.add_arguments(subparsers)

