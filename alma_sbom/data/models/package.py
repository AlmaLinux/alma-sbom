from dataclasses import dataclass
from enum import Enum
from logging import getLogger

from alma_sbom.type import Hash, PackageNevra
from alma_sbom.data.attributes.property import (
    Property,
    PackageProperties,
    BuildPropertiesForPackage as BuildProperties,
    SBOMProperties,
)

_logger = getLogger(__name__)

@dataclass
class Package:
    ### info as package component of SBOM
    package_nevra: PackageNevra = None
    source_rpm: str = None
    ###TODO: need to be rethink that 'package_timestamp' is actually nedded?
    ###TODO: need to rethink the 'type' of package_timestamp
    package_timestamp: int  = None
    hashs: list[Hash] = None

    ### properties (got from database?? (or include package info))
    package_properties: PackageProperties = None
    build_properties: BuildProperties = None
    sbom_properties: SBOMProperties = None

    def get_doc_name(self) -> str:
        return self.package_nevra.get_NEVR()

    def get_cpe23(self) -> str:
        return self.package_nevra.get_cpe23()

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

    def get_properties(self) -> list[Property]:
        return (self.package_properties.to_properties() if self.package_properties is not None else []) + \
               (self.build_properties.to_properties() if self.build_properties is not None else []) + \
               (self.sbom_properties.to_properties() if self.sbom_properties is not None else [])

