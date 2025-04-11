import argparse
import os
from dataclasses import dataclass, asdict

from alma_sbom.cli.config import CommonConfig

@dataclass
class PackageConfig(CommonConfig):
    rpm_package_hash: str = None
    rpm_package: str = None

    def __post_init__(self) -> None:
        self._validate()
        super().__post_init__()

    def _validate(self) -> None:
        if (self.rpm_package_hash is None and self.rpm_package is None) or \
           (self.rpm_package_hash is not None and self.rpm_package is not None):
            raise ValueError(
                'Unexpected situation has occurred. '
                'Either rpm_package_hash or rpm_package must be specified.'
            )
        if self.rpm_package and not os.path.exists(self.rpm_package):
            raise FileNotFoundError(f"File '{self.rpm_package}' not found")

    @classmethod
    def from_base(cls, base: CommonConfig, rpm_package_hash: str, rpm_package: str) -> 'PackageConfig':
        base_fields = vars(base)
        return cls(**base_fields, rpm_package_hash=rpm_package_hash, rpm_package=rpm_package)

    @classmethod
    def from_base_args(cls, base: CommonConfig, args: argparse.Namespace) -> 'PackageConfig':
        return cls.from_base(base, rpm_package_hash=args.rpm_package_hash, rpm_package=args.rpm_package)

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

