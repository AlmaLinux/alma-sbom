import argparse
from dataclasses import dataclass

from alma_sbom.cli.config import CommonConfig

@dataclass
class IsoConfig(CommonConfig):
    iso_image: str = None

    def __post_init__(self) -> None:
        self._validate()
        super().__post_init__()

    def _validate(self) -> None:
        if not self.iso_image:
            raise ValueError(
                'Unexpected situation has occurred'
                'iso_image must not be empty'
            )

    @classmethod
    def from_base(cls, base: CommonConfig, iso_image: str) -> 'BuildConfig':
        base_fields = vars(base)
        return cls(**base_fields, iso_image=iso_image)

    @classmethod
    def from_base_args(cls, base: CommonConfig, args: argparse.Namespace) -> 'BuildConfig':
        return cls.from_base(base, iso_image=args.iso_image)

    @staticmethod
    def add_arguments(parser: argparse._SubParsersAction) -> None:
        build_parser = parser.add_parser('iso', help='Generate ISO SBOM')
        build_parser.add_argument(
            '--iso-image',
            type=str,
            help='Path to AlmaLinux installer ISO9660 image',
            required=True,
        )
