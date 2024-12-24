from dataclasses import dataclass

@dataclass
class Property:
    name: str
    value: str

@dataclass
class BuildSourceProperties():
    source_type: str

    def to_properties(self) -> list[Property]:
        return [
            Property("almalinux:albs:build:source:type", self.source_type)
        ]

@dataclass
class GitSourceProperties(BuildSourceProperties):
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
        return super().to_properties() + [
            Property("almalinux:albs:build:source:gitCommit", self.git_commit),
            Property("almalinux:albs:build:source:gitCommitImmudbHash", self.git_commit_immudb_hash),
            Property("almalinux:albs:build:source:gitRef", self.git_ref),
            Property("almalinux:albs:build:source:gitURL", self.git_url),
        ]

@dataclass
class SrpmSourceProperties(BuildSourceProperties):
    srpm_url: str
    srpm_checksum: str
    srpm_nevra: str

    def __init__(self, srpm_url: str, srpm_checksum: str, srpm_nevra: str):
        super().__init__(source_type="srpm")
        self.srpm_url = srpm_url
        self.srpm_checksum = srpm_checksum
        self.srpm_nevra = srpm_nevra

    def to_properties(self) -> list[Property]:
        return super().to_properties() + [
            Property("almalinux:albs:build:source:srpmURL", self.srpm_url),
            Property("almalinux:albs:build:source:srpmChecksum", self.srpm_checksum),
            Property("almalinux:albs:build:source:srpmNEVRA", self.srpm_nevra),
        ]

@dataclass
class BuildProperties:
    target_arch: str
    package_type: str
    build_id: str
    build_url: str
    author: str
    source: BuildSourceProperties

    def to_properties(self) -> list[Property]:
        return [
            Property("almalinux:albs:build:ID", self.build_id),
            Property("almalinux:albs:build:URL", self.build_url),
            Property("almalinux:albs:build:author", self.author),
            Property("almalinux:albs:build:packageType", self.package_type),
            Property("almalinux:albs:build:targetArch", self.target_arch),
        ] + self.source.to_properties()

@dataclass
class PackageProperties:
    epoch: str
    version: str
    release: str
    arch: str
    buildhost: str
    sourcerpm: str
    timestamp: str

    def to_properties(self) -> list[Property]:
        return [
            Property("almalinux:package:epoch", self.epoch),
            Property("almalinux:package:version", self.version),
            Property("almalinux:package:release", self.release),
            Property("almalinux:package:arch", self.arch),
            Property("almalinux:package:buildhost", self.buildhost),
            Property("almalinux:package:sourcerpm", self.sourcerpm),
            Property("almalinux:package:timestamp", self.timestamp),
        ]

@dataclass
class SBOMProperties:
    immudb_hash: str

    def to_properties(self) -> list[Property]:
        return [
            Property("almalinux:sbom:immudbHash", self.immudb_hash),
        ]

