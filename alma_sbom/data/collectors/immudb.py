import os
from immudb_wrapper import ImmudbWrapper
from logging import getLogger

from alma_sbom.data.models.package import Hash, Algorithms
from alma_sbom.data import Package, Build, PackageNevra
from ..attributes.property import (
    PackageProperties,
    BuildSourceProperties,
    GitSourceProperties,
    SrpmSourceProperties,
    BuildProperties,
    SBOMProperties,
)

_logger = getLogger(__name__)

class ImmudbCollector:
    client: ImmudbWrapper

    def __init__(
         self,
         username: str = ImmudbWrapper.read_only_username(),
         password: str = ImmudbWrapper.read_only_password(),
         database: str = ImmudbWrapper.almalinux_database_name(),
         immudb_address: str = ImmudbWrapper.almalinux_database_address(),
         public_key_file: str = None,
     ):
         self.client = ImmudbWrapper(
             username=username or os.environ.get('IMMUDB_USERNAME'),
             password=password or os.environ.get('IMMUDB_PASSWORD'),
             database=database or os.environ.get('IMMUDB_DATABASE'),
             immudb_address=immudb_address or os.environ.get('IMMUDB_ADDRESS'),
             public_key_file=public_key_file or os.environ.get('IMMUDB_PUBLIC_KEY_FILE'),
         )

    def collect_package_by_hash(self, hash: str) -> Package:
        immudb_info = self._extract_immudb_info_about_package(hash=hash)

        ### need to be rethink below
        hash = hash or immudb_info['Hash']
        hashs = Hash(algorithm=Algorithms.SHA_256, value=hash)

        if 'Metadata' in immudb_info:
            immudb_metadata = immudb_info['Metadata']
        else:
            return None

        api_ver = immudb_metadata.get('sbom_api_ver')
        if not api_ver:
            api_ver = immudb_metadata.get('sbom_api')
        if not api_ver:
            raise ValueError('Immudb metadata is malformed, API version cannot be detected')

        package = None
        if api_ver == '0.1':
            package = self._get_package_apiver01(immudb_info, hashs)
        elif api_ver == '0.2':
            package = self._get_package_apiver02(immudb_info, hashs)
        else:
            raise ValueError(f'Malicious api_ver: {api_ver}')

        return package

    def _get_package_apiver01(self, immudb_info: dict, hashs: Hash) -> Package:
        ### TODO:
        # need to rethink func structure
        if 'Metadata' in immudb_info:
            immudb_metadata = immudb_info['Metadata']
        else: ### need to implement errro handling
            return None

        package_name = immudb_info['Name']
        package_nevra = PackageNevra.from_str_nothas_epoch(package_name)
        pkg_props, build_props, sbom_props = self._properties_from_immudb_info_about_package_apiver01(immudb_info, package_nevra)

        #raise NotImplementedError()

        package = Package(
            package_nevra = package_nevra,
            source_rpm = None,
            hashs = [hashs],
            package_timestamp = immudb_info['timestamp'],
            package_properties = pkg_props,
            build_properties = build_props,
            sbom_properties = sbom_props,
        )
        return package

    def _get_package_apiver02(self, immudb_info: dict, hashs: Hash) -> Package:
        ### TODO:
        # need to rethink func structure
        if 'Metadata' in immudb_info:
            immudb_metadata = immudb_info['Metadata']
        else: ### need to implement errro handling
            return None

        package_nevra = PackageNevra(
            epoch=immudb_metadata['epoch'],
            name = immudb_metadata['name'],
            version = immudb_metadata['version'],
            release = immudb_metadata['release'],
            arch = immudb_metadata['arch'],
        )
        pkg_props, build_props, sbom_props = self._properties_from_immudb_info_about_package_apiver02(immudb_info)

        package = Package(
            package_nevra = package_nevra,
            source_rpm = immudb_metadata['sourcerpm'],
            hashs = [hashs],
            package_timestamp = immudb_info['timestamp'],
            package_properties = pkg_props,
            build_properties = build_props,
            sbom_properties = sbom_props,
        )
        return package

    def collect_package_by_package(self, rpm_package: str) -> Package:
        immudb_info = self._extract_immudb_info_about_package(rpm_package=rpm_package)
        raise NotImplementedError()

    def collect_build_by_id(self, build_id: str) -> Build:
        raise NotImplementedError()

    def _extract_immudb_info_about_package(self, hash: str = None, rpm_package: str = None) -> dict:
        response = {}
        if hash != None :
            response = self.client.authenticate(hash)
        elif rpm_package != None :
            ### below validation need to be done in other class(Config?)
            #if not os.path.exists(rpm_package):
            #_logger.error(f'File {rpm_package} Not Found')
            #sys.exit(1)
            response = self.client.authenticate_file(rpm_package)
        result = response.get('value', {})
        result['timestamp'] = response.get('timestamp')
        return result

    def _properties_from_immudb_info_about_package_apiver01(self, immudb_info: dict, package_nevra: PackageNevra) -> tuple[
                PackageProperties,
                BuildProperties,
                SBOMProperties,
        ]:
        if 'Metadata' in immudb_info:
            immudb_metadata = immudb_info['Metadata']
        else: ### need to implement errro handling
            return None

        pkg_props = PackageProperties(
            epoch=None,
            version=package_nevra.version,
            release=package_nevra.release,
            arch=package_nevra.arch,
            buildhost=immudb_metadata['build_host'],
            sourcerpm=None,
            timestamp=immudb_info['timestamp'],
        )

        ### TODO:
        # rewrite as other func or/and in other files
        build_src_props = None
        if immudb_metadata['source_type'] == 'git':
            build_src_props = GitSourceProperties(
               git_url=immudb_metadata['git_url'],
               git_commit=immudb_metadata['git_url'],
               git_ref=immudb_metadata['git_ref'],
               git_commit_immudb_hash=immudb_metadata['alma_commit_sbom_hash'],
            )
        elif immudb_metadata['source_type'] == 'srpm':
            build_src_props = SrpmSourceProperties(
               srpm_url=immudb_metadata['srpm_url'],
               srpm_checksum=immudb_metadata['srpm_sha256'],
               srpm_nevra=immudb_metadata['srpm_nevra'],
            )
        else:
            raise ValueError(f"Unknown source_type: {immudb_metadata['source_type']}")
        build_props = BuildProperties(
            target_arch=immudb_metadata['build_arch'],
            package_type='rpm',
            build_id=immudb_metadata['build_id'],
            ### TODO:
            # set collect build_url
            #build_url=f'{albs_url}/build/{immudb_metadata["build_id"]}',
            build_url='https://dummy.almalinux.org',  ### dummy
            author=immudb_metadata['built_by'],
            source=build_src_props,
        )

        sbom_props = SBOMProperties(immudb_hash=immudb_info['Hash'])

        return pkg_props, build_props, sbom_props

    def _properties_from_immudb_info_about_package_apiver02(self, immudb_info: dict) -> tuple[
                PackageProperties,
                BuildProperties,
                SBOMProperties,
        ]:
        if 'Metadata' in immudb_info:
            immudb_metadata = immudb_info['Metadata']
        else: ### need to implement errro handling
            return None

        pkg_props = PackageProperties(
            ### TODO:
            # need to rethink what is 'epoch=None'
            # In api_ver==0.1, the record for epoch does not exist, so it will be None.
            # In api_ver==0.2, the record for epoch exist,
            # if immudb_metadata['epoch']==None, then what should we do?
            # According to the RPM specification, is it acceptable to consider None as equivalent to 0?
            epoch=immudb_metadata['epoch'],
            version=immudb_metadata['version'],
            release=immudb_metadata['release'],
            arch=immudb_metadata['arch'],
            buildhost=immudb_metadata['build_host'],
            sourcerpm=immudb_metadata['sourcerpm'],
            timestamp=immudb_info['timestamp'],
        )

        ### TODO:
        # rewrite as other func or/and in other files
        build_src_props = None
        if immudb_metadata['source_type'] == 'git':
            build_src_props = GitSourceProperties(
               git_url=immudb_metadata['git_url'],
               git_commit=immudb_metadata['git_url'],
               git_ref=immudb_metadata['git_ref'],
               git_commit_immudb_hash=immudb_metadata['alma_commit_sbom_hash'],
            )
        elif immudb_metadata['source_type'] == 'srpm':
            build_src_props = SrpmSourceProperties(
               srpm_url=immudb_metadata['srpm_url'],
               srpm_checksum=immudb_metadata['srpm_sha256'],
               srpm_nevra=immudb_metadata['srpm_nevra'],
            )
        else:
            raise ValueError(f"Unknown source_type: {immudb_metadata['source_type']}")
        build_props = BuildProperties(
            target_arch=immudb_metadata['build_arch'],
            package_type='rpm',
            build_id=immudb_metadata['build_id'],
            ### TODO:
            # set collect build_url
            #build_url=f'{albs_url}/build/{immudb_metadata["build_id"]}',
            build_url='https://dummy.almalinux.org',  ### dummy
            author=immudb_metadata['built_by'],
            source=build_src_props,
        )

        sbom_props = SBOMProperties(immudb_hash=immudb_info['Hash'])

        return pkg_props, build_props, sbom_props

