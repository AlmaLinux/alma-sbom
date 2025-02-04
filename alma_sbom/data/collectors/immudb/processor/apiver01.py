from .processor import DataProcessor

from alma_sbom.type import Hash, Algorithms
from alma_sbom.data import Package, Build, PackageNevra
from alma_sbom.data.attributes.property import (
    PackageProperties,
    BuildSourceProperties,
    GitSourceProperties,
    SrpmSourceProperties,
    BuildPropertiesForPackage as BuildProperties,
    SBOMProperties,
)

class DataProcessor01(DataProcessor):
    immudb_info: dict
    immudb_metadata: dict
    hash: Hash

    def get_api_ver(self) -> str:
        return '0.1'

    def get_package(self) -> Package:
        package_name = self.immudb_info['Name']
        package_nevra = PackageNevra.from_str_nothas_epoch(package_name)
        pkg_props, build_props, sbom_props = self._properties_from_immudb_info_about_package(package_nevra)

        return Package(
            package_nevra = package_nevra,
            source_rpm = None,
            hashs = [self.hash],
            package_timestamp = self.immudb_info['timestamp'],
            package_properties = pkg_props,
            build_properties = build_props,
            sbom_properties = sbom_props,
        )

    def _properties_from_immudb_info_about_package(self, package_nevra: PackageNevra) -> tuple[
                PackageProperties,
                BuildProperties,
                SBOMProperties,
        ]:
        pkg_props = PackageProperties(
            epoch=None,
            version=package_nevra.version,
            release=package_nevra.release,
            arch=package_nevra.arch,
            buildhost=self.immudb_metadata['build_host'],
            sourcerpm=None,
            timestamp=self.immudb_info['timestamp'],
        )

        build_src_props = None
        if self.immudb_metadata['source_type'] == 'git':
            build_src_props = GitSourceProperties(
               git_url=self.immudb_metadata['git_url'],
               git_commit=self.immudb_metadata['git_url'],
               git_ref=self.immudb_metadata['git_ref'],
               git_commit_immudb_hash=self.immudb_metadata['alma_commit_sbom_hash'],
            )
        elif self.immudb_metadata['source_type'] == 'srpm':
            build_src_props = SrpmSourceProperties(
               srpm_url=self.immudb_metadata['srpm_url'],
               srpm_checksum=self.immudb_metadata['srpm_sha256'],
               srpm_nevra=self.immudb_metadata['srpm_nevra'],
            )
        else:
            raise ValueError(f"Unknown source_type: {self.immudb_metadata['source_type']}")
        build_props = BuildProperties(
            target_arch=self.immudb_metadata['build_arch'],
            package_type='rpm',
            build_id=self.immudb_metadata['build_id'],
            ### TODO:
            # set collect build_url
            # how to get albs_url??
            #build_url=f'{albs_url}/build/{immudb_metadata["build_id"]}',
            build_url='https://dummy.almalinux.org',  ### dummy
            author=self.immudb_metadata['built_by'],
            source=build_src_props,
        )

        sbom_props = SBOMProperties(immudb_hash=self.immudb_info['Hash'])

        return pkg_props, build_props, sbom_props

