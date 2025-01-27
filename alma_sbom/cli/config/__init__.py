import argparse

from .config import CommonConfig
from .models import (
    PackageConfig,
    BuildConfig,
    setup_subparsers,
)

def add_config_arguments(parser: argparse.ArgumentParser) -> None:
    CommonConfig.add_arguments(parser)
    subparsers = parser.add_subparsers(dest='command', required=True)
    setup_subparsers(subparsers)

