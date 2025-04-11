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
from .utils import normalize_epoch

class DataProcessor02(DataProcessor):
    immudb_info: dict
    immudb_metadata: dict
    hash: Hash

    def get_api_ver(self) -> str:
        return '0.2'

    def get_package(self) -> Package:
        package_nevra = PackageNevra(
            ### NOTE:
            # Due to uncertainty about whether missing epoch field in the database'
            # can be treated as equivalent to 0, Now we store None for missing epoch
            # field at this time.
            epoch = normalize_epoch(self.immudb_metadata['epoch']) if 'epoch' in self.immudb_metadata else None,
            name = self.immudb_metadata.get('name'),
            version = self.immudb_metadata.get('version'),
            release = self.immudb_metadata.get('release'),
            arch = self.immudb_metadata.get('arch'),
        )
        pkg_props, build_props, sbom_props = self._properties_from_immudb_info_about_package()

        return Package(
            package_nevra = package_nevra,
            source_rpm = self.immudb_metadata.get('sourcerpm'),
            hashs = [self.hash],
            package_timestamp = self.immudb_info.get('timestamp'),
            package_properties = pkg_props,
            build_properties = build_props,
            sbom_properties = sbom_props,
        )

    def _properties_from_immudb_info_about_package(self) -> tuple[
                PackageProperties,
                BuildProperties,
                SBOMProperties,
        ]:
        pkg_props = PackageProperties(
            ### NOTE:
            # Due to uncertainty about whether missing epoch field in the database'
            # can be treated as equivalent to 0, Now we store None for missing epoch
            # field at this time.
            epoch = normalize_epoch(self.immudb_metadata['epoch']) if 'epoch' in self.immudb_metadata else None,
            version=self.immudb_metadata.get('version'),
            release=self.immudb_metadata.get('release'),
            arch=self.immudb_metadata.get('arch'),
            buildhost=self.immudb_metadata.get('build_host'),
            sourcerpm=self.immudb_metadata.get('sourcerpm'),
            timestamp=self.immudb_info.get('timestamp'),
        )

        build_src_props = None
        source_type = self.immudb_metadata.get('source_type')
        if source_type == 'git':
            build_src_props = GitSourceProperties(
               git_url=self.immudb_metadata.get('git_url'),
               git_commit=self.immudb_metadata.get('git_url'),
               git_ref=self.immudb_metadata.get('git_ref'),
               git_commit_immudb_hash=self.immudb_metadata.get('alma_commit_sbom_hash'),
            )
        elif source_type == 'srpm':
            build_src_props = SrpmSourceProperties(
               srpm_url=self.immudb_metadata.get('srpm_url'),
               srpm_checksum=self.immudb_metadata.get('srpm_sha256'),
               srpm_nevra=self.immudb_metadata.get('srpm_nevra'),
            )
        else:
            raise ValueError(f'Unknown source_type: {source_type}')

        build_props = BuildProperties(
            target_arch=self.immudb_metadata.get('build_arch'),
            package_type='rpm',
            build_id=self.immudb_metadata.get('build_id'),
            ### Please See https://github.com/AlmaLinux/build-system/issues/425 why build_url=None
            build_url=None,
            author=self.immudb_metadata.get('built_by'),
            source=build_src_props,
        )

        sbom_props = SBOMProperties(immudb_hash=self.immudb_info.get('Hash'))

        return pkg_props, build_props, sbom_props

