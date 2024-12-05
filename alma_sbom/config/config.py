import argparse
from dataclasses import dataclass
from enum import Enum
from typing import Union
from logging import DEBUG, INFO, WARNING

from ..formats.spdx.models import SPDXFormat
from ..formats.cyclonedx.models import CDXFormat

@dataclass
class SBOMFormat(Enum):
    SPDX = 'spdx'
    CYCLONEDX = 'cyclonedx'

@dataclass
class CommonConfig:
    loglevel: int = INFO
    output_file: str = None
    #sbom_format: SBOMFormat
    #file_format: Union[SPDXFormat, CDXFormat]

