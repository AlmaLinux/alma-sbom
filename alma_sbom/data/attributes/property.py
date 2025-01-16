from dataclasses import dataclass
from typing import ClassVar

@dataclass
class Property:
    name: str
    value: str

class PropertyMixin:
    """Mixin for providing common functionality for property conversion"""
    PROPERTY_KEYS: ClassVar[dict[str, str]] = {}

    def _create_properties(self) -> list[Property]:
        """Create a property list from instance variables"""
        return [
            Property(self.PROPERTY_KEYS[attr], getattr(self, attr))
            for attr in self.PROPERTY_KEYS
            if getattr(self, attr) is not None
        ]

@dataclass
class BuildSourceProperties(PropertyMixin):
    PROPERTY_KEYS: ClassVar[dict[str, str]] = {
        "source_type": "almalinux:albs:build:source:type"
    }

    source_type: str

    def to_properties(self) -> list[Property]:
        return self._create_properties()

@dataclass
class GitSourceProperties(BuildSourceProperties):
    PROPERTY_KEYS: ClassVar[dict[str, str]] = {
        **BuildSourceProperties.PROPERTY_KEYS,
        "git_commit": "almalinux:albs:build:source:gitCommit",
        "git_commit_immudb_hash": "almalinux:albs:build:source:gitCommitImmudbHash",
        "git_ref": "almalinux:albs:build:source:gitRef",
        "git_url": "almalinux:albs:build:source:gitURL"
    }

    git_url: str
    git_commit: str
    git_ref: str
    git_commit_immudb_hash: str

    def __init__(self, git_url: str, git_commit: str, git_ref: str, git_commit_immudb_hash: str):
        super().__init__(source_type="git")
        self.git_url = git_url
        self.git_commit = git_commit
        self.git_ref = git_ref
        self.git_commit_immudb_hash = git_commit_immudb_hash

    def to_properties(self) -> list[Property]:
        return self._create_properties()

@dataclass
class SrpmSourceProperties(BuildSourceProperties):
    PROPERTY_KEYS: ClassVar[dict[str, str]] = {
        **BuildSourceProperties.PROPERTY_KEYS,
        "srpm_url": "almalinux:albs:build:source:srpmURL",
        "srpm_checksum": "almalinux:albs:build:source:srpmChecksum",
        "srpm_nevra": "almalinux:albs:build:source:srpmNEVRA"
    }

    srpm_url: str
    srpm_checksum: str
    srpm_nevra: str

    def __init__(self, srpm_url: str, srpm_checksum: str, srpm_nevra: str):
        super().__init__(source_type="srpm")
        self.srpm_url = srpm_url
        self.srpm_checksum = srpm_checksum
        self.srpm_nevra = srpm_nevra

    def to_properties(self) -> list[Property]:
        return self._create_properties()

@dataclass
class BuildPropertiesBase(PropertyMixin):
    PROPERTY_KEYS: ClassVar[dict[str, str]] = {
        "build_id": "almalinux:albs:build:ID",
        "build_url": "almalinux:albs:build:URL",
    }

    build_id: str
    build_url: str

    def to_properties(self) -> list[Property]:
        return self._create_properties()

@dataclass
class BuildPropertiesForPackage(BuildPropertiesBase):
    PROPERTY_KEYS: ClassVar[dict[str, str]] = {
        **BuildPropertiesBase.PROPERTY_KEYS,
        "author": "almalinux:albs:build:author",
        "package_type": "almalinux:albs:build:packageType",
        "target_arch": "almalinux:albs:build:targetArch"
    }

    author: str
    package_type: str
    target_arch: str
    source: BuildSourceProperties

    def to_properties(self) -> list[Property]:
        return self._create_properties() + (self.source.to_properties() if self.source is not None else [])

@dataclass
class BuildPropertiesForBuild(BuildPropertiesBase):
    PROPERTY_KEYS: ClassVar[dict[str, str]] = {
        **BuildPropertiesBase.PROPERTY_KEYS,
        "timestamp": "almalinux:albs:build:timestamp"
    }

    timestamp: str

    def to_properties(self) -> list[Property]:
        return self._create_properties()

@dataclass
class PackageProperties(PropertyMixin):
    PROPERTY_KEYS: ClassVar[dict[str, str]] = {
        "arch": "almalinux:package:arch",
        "buildhost": "almalinux:package:buildhost",
        "epoch": "almalinux:package:epoch",
        "release": "almalinux:package:release",
        "sourcerpm": "almalinux:package:sourcerpm",
        "timestamp": "almalinux:package:timestamp",
        "version": "almalinux:package:version"
    }

    epoch: str
    version: str
    release: str
    arch: str
    buildhost: str
    sourcerpm: str
    timestamp: str

    def to_properties(self) -> list[Property]:
        return self._create_properties()

@dataclass
class SBOMProperties(PropertyMixin):
    PROPERTY_KEYS: ClassVar[dict[str, str]] = {
        "immudb_hash": "almalinux:sbom:immudbHash"
    }

    immudb_hash: str

    def to_properties(self) -> list[Property]:
        return self._create_properties()

