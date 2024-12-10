import argparse
from dataclasses import dataclass
from enum import Enum
from typing import Union
from logging import getLogger

from ..formats.spdx.models import SPDXFormat
from ..formats.cyclonedx.models import CDXFormat

_logger = getLogger(__name__)

@dataclass
class SBOMFormat(Enum):
    SPDX = 'spdx'
    CYCLONEDX = 'cyclonedx'

@dataclass
class CommonConfig:
    output_file: str = None
    #sbom_format: SBOMFormat
    #file_format: Union[SPDXFormat, CDXFormat]

    def __post_init__(self):
        _logger.debug("CommonConfig.__post_init__")


