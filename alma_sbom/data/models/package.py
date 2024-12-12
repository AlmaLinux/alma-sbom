from dataclasses import dataclass

@dataclass
class PackageNevra:
    epoch: str = None
    name: str = None
    version: str = None
    release: str = None
    arch: str = None

    def __repr__(self):
        if self.epoch is not None:
            return (
                f'{self.epoch}:{self.name}-'
                f'{self.version}-{self.release}.{self.arch}'
            )
        return f'{self.name}-{self.version}-' f'{self.release}.{self.arch}'

@dataclass
class PackageSourceInfo:
    pass

@dataclass
class GitSourceInfo(PackageSourceInfo):
    source_type: str = 'git'
    git_url: str = None
    git_commit: str = None
    git_ref: str = None
    git_commit_immudb_hash: str = None

@dataclass
class SrpmSourceInfo(PackageSourceInfo):
    source_type: str = 'srpm'
    srpm_url: str = None
    srpm_checksum: str = None
    srpm_nevra: str = None


@dataclass
class Package:
    ### required data
    package_nevra: PackageNevra = None
    source_rpm: str = None
    ### package info
    package_timestamp: str  = None
    package_type: str = None
    immudb_hash: str = None

    ### build info
    build_host: str = None
    build_arch: str = None
    build_id: str = None
    build_author: str = None

    ### source info
    source_info: PackageSourceInfo = None

