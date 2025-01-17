import argparse
from logging import getLogger

from alma_sbom.data import DataCollector, data_collector_factory
from alma_sbom.config.config import CommonConfig
from alma_sbom.config.models.build import BuildConfig
from alma_sbom.formats import Document, document_factory
from .commands import SubCommand

_logger = getLogger(__name__)

class BuildCommand(SubCommand):
    config: BuildConfig
    doc: Document
    collector: DataCollector

    def __init__(self, base: CommonConfig, args: argparse.Namespace) -> None:
        self.config = self._get_BuildConfig_from_args(base, args)
        self.collector = data_collector_factory(self.config)

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
        build = self.collector.run()
        document_class = document_factory(self.config.sbom_type.record_type)
        self.doc = document_class.from_build(build, self.config.sbom_type.file_format_type)
        self.doc.write(self.config.output_file)
        return 0

    @staticmethod
    def _get_BuildConfig_from_args(base: CommonConfig, args: argparse.Namespace) -> BuildConfig:
        return BuildConfig.from_base(base, build_id=args.build_id)

