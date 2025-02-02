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

    def get_purl(self) -> str:
        base_part = self.package_nevra.get_purl()
        qualifier_part = ''
        if self.source_rpm:
            qualifier_part += f'&upstream={self.source_rpm}'

        return f'{base_part}{qualifier_part}'

    def get_properties(self) -> list[Property]:
        return (self.package_properties.to_properties() if self.package_properties is not None else []) + \
               (self.build_properties.to_properties() if self.build_properties is not None else []) + \
               (self.sbom_properties.to_properties() if self.sbom_properties is not None else [])

