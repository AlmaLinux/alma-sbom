import argparse
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

class SbomRecordType(Enum):
    SPDX = 'spdx'
    CYCLONEDX = 'cyclonedx'

    @classmethod
    def from_str(cls, string: str) -> 'SbomRecordType':
        for record_type in cls:
            if string == record_type.value:
                return record_type
        raise ValueError('Invalid SbomRecoredType string')

class SbomFileFormatType(Enum):
    JSON = 'json'
    TAGVALUE = 'tagvalue'
    XML = 'xml'
    YAML = 'yaml'

    @classmethod
    def from_str(cls, string: str) -> 'SbomFileFormatType':
        for record_format in cls:
            if string == record_format.value:
                return record_format
        raise ValueError('Invalid SbomFileFormatType string')

class SbomType:
    VALID_SBOM_TYPE: dict[SbomRecordType, list[SbomFileFormatType]] = {
        SbomRecordType.SPDX: [
            SbomFileFormatType.JSON,
            SbomFileFormatType.XML,
            SbomFileFormatType.YAML,
            SbomFileFormatType.TAGVALUE,
        ],
        SbomRecordType.CYCLONEDX: [
            SbomFileFormatType.JSON,
            SbomFileFormatType.XML,
        ],
    }
    record_type: SbomRecordType
    file_format_type: SbomFileFormatType

    def __init__(
        self,
        record_type: SbomRecordType = SbomRecordType.SPDX,
        file_format_type: SbomFileFormatType = SbomFileFormatType.JSON,
    ):
        self.record_type = record_type
        self.file_format_type = file_format_type
        self._validate()

    @classmethod
    def from_each_str(cls, record_type: str, file_format_type: str) -> 'SbomType':
        return cls(
            SbomRecordType.from_str(record_type),
            SbomFileFormatType.from_str(file_format_type),
        )

    @classmethod
    def from_str(cls, string: str) -> 'SbomType':
        try:
            record_type, file_format_type = string.split('-')
        except ValueError:
            raise argparse.ArgumentTypeError('Invalid SBOM type format. Use "record_type-file_format"')
        return cls.from_each_str(
            record_type,
            file_format_type,
        )

    def _validate(self) -> None:
        if self.file_format_type not in self.VALID_SBOM_TYPE[self.record_type]:
            raise ValueError(
                f"Invalid Sbom Type: "
                f"{self.record_type.value}-{self.file_format_type.value}"
            )

    @classmethod
    def choices(cls) -> list:
        return [f'{rt}-{ff}' for rt, ff in cls.get_valid_sbom_type()]

    @classmethod
    def get_valid_sbom_type(cls) -> list[tuple[str, str]]:
        return [
            (record_type.value, file_format.value)
            for record_type, file_formats in cls.VALID_SBOM_TYPE.items()
            for file_format in file_formats
        ]

    def values(self) -> tuple[Enum, ...]:
        return tuple([self.record_type, self.file_format_type])

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SbomType):
            return (
                self.record_type == other.record_type
                and self.file_format_type == other.file_format_type
            )
        return False

    def __repr__(self) -> str:
        return f"{self.record_type.value}-{self.file_format_type.value}"

### See the pythondx-python-libs Document: https://cyclonedx-python-library.readthedocs.io/en/latest/autoapi/cyclonedx/model/index.html#cyclonedx.model.HashAlgorithm
class Algorithms(Enum):
    SHA_256 = 'SHA-256'

    @classmethod
    def from_str(cls, string: str) -> 'Algorithms':
        for alg in cls:
            if string == alg.value:
                return alg
        raise ValueError(f'Invalid Algorithms string: {string}')

@dataclass
class Hash:
    value: str
    algorithm: Algorithms = Algorithms.SHA_256

@dataclass
class PackageNevra:
    name: str
    epoch: Optional[int]
    version: str
    release: str
    arch: str

    def __repr__(self):
        if self.epoch is not None:
            return (
                f'{self.epoch}:{self.name}-'
                f'{self.version}-{self.release}.{self.arch}'
            )
        return f'{self.name}-{self.version}-' f'{self.release}.{self.arch}'

    def get_NEVR(self) -> str:
        if self.epoch is not None:
            return (
                f'{self.epoch}:{self.name}-{self.version}-{self.release}'
            )
        return f'{self.name}-{self.version}-{self.release}'

    def get_EVR(self) -> str:
        if self.epoch is not None:
            return (
                f'{self.epoch}:{self.version}-{self.release}'
            )
        return f'{self.version}-{self.release}'

    def get_cpe23(self) -> str:
        cpe_version = '2.3'
        cpe_epoch_part = f'{self.epoch if self.epoch else ""}'
        cpe_epoch_part += '\\:' if cpe_epoch_part else ""
        cpe = (
            f'cpe:{cpe_version}:a:almalinux:'
            f'{self._escape_encode_cpe_part(self.name)}:{cpe_epoch_part}'
            f'{self._escape_encode_cpe_part(self.version)}-'
            f'{self._escape_encode_cpe_part(self.release)}:*:*:*:*:*:*:*'
        )
        return cpe

    def get_purl(self) -> str:
        # https://github.com/AlmaLinux/build-system-rfes/commit/a132ececa1d7901fe42348022ce954d475578920
        if self.epoch:
            purl_epoch_part = f'&epoch={self.epoch}'
        else:
            purl_epoch_part = ''
        purl = (
            f'pkg:rpm/almalinux/{self.name}@{self.version}-'
            f'{self.release}?arch={self.arch}{purl_epoch_part}'
        )
        return purl

    @classmethod
    def from_str_has_epoch(package_name: str) -> 'PackageNevra':
        raise NotImplementedError()

    @classmethod
    def from_str_nothas_epoch(cls, package_name: str) -> 'PackageNevra':
        split_by_dot = package_name.replace('.rpm', '')[::-1].split('.', 1)
        arch = split_by_dot[0][::-1]
        split_by_hyphen = split_by_dot[1].split('-', 2)
        release = split_by_hyphen[0][::-1]
        version = split_by_hyphen[1][::-1]
        name = split_by_hyphen[2][::-1]

        return cls(
            epoch = None,
            name = name,
            version = version,
            release = release,
            arch = arch,
        )

    @staticmethod
    def _escape_encode_cpe_part(cpe: str) -> str:
        """Escape special characters in cpe each part in accordance with the spdx-tools validation"""
        allowed_chars = r'a-zA-Z0-9\-\._'
        escape_chars = r'\\*?!"#$%&\'()+,/:;<=>@[]^`{|}~'

        def encode_char(match):
            char = match.group(0)
            if char in escape_chars:
                return '\\' + char

        return re.sub(f'[^{allowed_chars}]', encode_char, cpe)

@dataclass
class Licenses:
    ids: list[str]
    expression: str

