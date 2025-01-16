from .processor import DataProcessor

from alma_sbom.data import Package, Build, PackageNevra
from alma_sbom.data.models.package import Hash, Algorithms
from alma_sbom.data.attributes.property import (
    PackageProperties,
    BuildSourceProperties,
    GitSourceProperties,
    SrpmSourceProperties,
    BuildPropertiesForPackage as BuildProperties,
    SBOMProperties,
)

class DataProcessor02(DataProcessor):
    immudb_info: dict
    immudb_metadata: dict
    hash: Hash

    def get_api_ver(self) -> str:
        return '0.2'

    def get_package(self) -> Package:
        package_nevra = PackageNevra(
            epoch = self.immudb_metadata['epoch'],
            name = self.immudb_metadata['name'],
            version = self.immudb_metadata['version'],
            release = self.immudb_metadata['release'],
            arch = self.immudb_metadata['arch'],
        )
        pkg_props, build_props, sbom_props = self._properties_from_immudb_info_about_package()

        return Package(
            package_nevra = package_nevra,
            source_rpm = self.immudb_metadata['sourcerpm'],
            hashs = [self.hash],
            package_timestamp = self.immudb_info['timestamp'],
            package_properties = pkg_props,
            build_properties = build_props,
            sbom_properties = sbom_props,
        )

    def get_build(self) -> Build: ###?
        raise NotImplementedError()

    def _properties_from_immudb_info_about_package(self) -> tuple[
                PackageProperties,
                BuildProperties,
                SBOMProperties,
        ]:
        pkg_props = PackageProperties(
            ### TODO:
            # need to rethink what is 'epoch=None'
            # In api_ver==0.1, the record for epoch does not exist, so it will be None.
            # In api_ver==0.2, the record for epoch exist,
            # if immudb_metadata['epoch']==None, then what should we do?
            # According to the RPM specification, is it acceptable to consider None as equivalent to 0?
            epoch=self.immudb_metadata['epoch'],
            version=self.immudb_metadata['version'],
            release=self.immudb_metadata['release'],
            arch=self.immudb_metadata['arch'],
            buildhost=self.immudb_metadata['build_host'],
            sourcerpm=self.immudb_metadata['sourcerpm'],
            timestamp=self.immudb_info['timestamp'],
        )

        ### TODO:
        # rewrite as other func or/and in other files
        build_src_props = None
        if self.immudb_metadata['source_type'] == 'git':
            build_src_props = GitSourceProperties(
               git_url=self.immudb_metadata['git_url'],
               git_commit=self.immudb_metadata['git_url'],
               git_ref=self.immudb_metadata['git_ref'],
               git_commit_immudb_hash=self.immudb_metadata['alma_commit_sbom_hash'],
            )
        elif immudb_metadata['source_type'] == 'srpm':
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
            #build_url=f'{albs_url}/build/{immudb_metadata["build_id"]}',
            build_url='https://dummy.almalinux.org',  ### dummy
            author=self.immudb_metadata['built_by'],
            source=build_src_props,
        )

        sbom_props = SBOMProperties(immudb_hash=self.immudb_info['Hash'])

        return pkg_props, build_props, sbom_props

