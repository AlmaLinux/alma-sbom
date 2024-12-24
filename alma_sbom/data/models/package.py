from dataclasses import dataclass

from ..attributes.property import PackageProperties, BuildProperties, SBOMProperties

@dataclass
class PackageNevra:
    name: str = None
    epoch: str = None
    version: str = None
    release: str = None
    arch: str = None

    ### TODO:
    # rethink if self.epoch logic below 3 funcs
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

    ### TODO:
    ## item 1
    # need to be implemented out of PackageNevra or more outer ??
    ## item 2
    # need to be applied fix of normalize_epoch_in_cpe
    # -> this need to be corvered by PackageNevra.epoch=='None'(str) ??
    def get_cpe23(self) -> str:
        cpe_version = '2.3'

        cpe_epoch_part = f'{self.epoch if self.epoch else ""}'
        cpe_epoch_part += '\\:' if cpe_epoch_part else ""
        cpe = (
            f'cpe:{cpe_version}:a:almalinux:'
            f'{self.name}:{cpe_epoch_part}'
            f'{self.version}-{self.release}:*:*:*:*:*:*:*'
        )
        return cpe

@dataclass
class Package:
    ### info as package component of SBOM
    package_nevra: PackageNevra = None
    source_rpm: str = None
    ### need to be rethink that 'package_timestamp' is actually nedded?
    package_timestamp: str  = None
    hash: str = None

    ### properties (got from database?? (or include package info))
    package_properties: PackageProperties = None
    build_properties: BuildProperties = None
    sbom_properties: SBOMProperties = None

    ### TODO
    # need to be defined in PackageNevra class??
    def get_doc_name(self) -> str:
        return self.package_nevra.get_NEVR()

    ### TODO
    ## item 1
    # need to be implemented out of Package class??
    ## item 2
    # need to be applied fix of normalize_epoch_in_purl
    # -> this need to be corvered by PackageNevra.epoch=='None'(str) ??
    def get_purl(self) -> str:
        # https://github.com/AlmaLinux/build-system-rfes/commit/a132ececa1d7901fe42348022ce954d475578920
        if self.package_nevra.epoch:
            purl_epoch_part = f'&epoch={self.package_nevra.epoch}'
        else:
            purl_epoch_part = ''
        if self.source_rpm:
            purl_upstream_part = f'&upstream={self.source_rpm}'
        else:
            purl_upstream_part = ''
        purl = (
            f'pkg:rpm/almalinux/{self.package_nevra.name}@{self.package_nevra.version}-'
            f'{self.package_nevra.release}?arch={self.package_nevra.arch}'
            f'{purl_epoch_part}{purl_upstream_part}'
        )
        return purl
