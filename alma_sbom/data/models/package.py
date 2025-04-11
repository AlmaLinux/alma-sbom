from dataclasses import dataclass
from enum import Enum
from logging import getLogger

from alma_sbom.type import Hash, PackageNevra, Licenses
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
    ###TODO: need to rethink the 'type' of package_timestamp
    package_timestamp: int  = None
    hashs: list[Hash] = None

    ### additional info (from package) as package componet of SBOM
    licenses: Licenses = None
    summary: str = None
    description: str = None

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

    #@classmethod
    def merge(self, pkg2: 'Package') -> 'Package':
        ### TODO:
        # what should i do, when there are difference between these packages
        return Package(
            package_nevra = self.package_nevra or pkg2.package_nevra,
            source_rpm = self.source_rpm or pkg2.source_rpm,
            package_timestamp = self.package_timestamp or pkg2.package_timestamp,
            hashs = self.hashs or pkg2.hashs, ### need to rethink if there were multiple data in the future
            licenses = self.licenses or pkg2.licenses,
            summary = self.summary or pkg2.summary,
            description = self.description or pkg2.description,
            package_properties = self.package_properties or pkg2.package_properties,
            build_properties = self.build_properties or pkg2.build_properties,
            sbom_properties = self.sbom_properties or pkg2.sbom_properties,
        )

NullPackage = Package()

