
import os
from immudb_wrapper import ImmudbWrapper

#from alma_sbom.data.models import Package, Build, PackageNevra
from alma_sbom.data import Package, Build, PackageNevra

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

        if 'Metadata' in immudb_info:
            immudb_metadata = immudb_info['Metadata']
        else:
            return None

        api_ver = immudb_metadata.get('sbom_api_ver')
        if not api_ver:
            api_ver = immudb_metadata.get('sbom_api')
        if not api_ver:
            raise ValueError('Immudb metadata is malformed, API version cannot be detected')

        package_nevra = PackageNevra(
            epoch = None,
            name = immudb_metadata['name'],
            version = immudb_metadata['version'],
            release = immudb_metadata['release'],
            arch = immudb_metadata['arch'],
        )
        package = Package(
            package_nevra = package_nevra,
            source_rpm = immudb_metadata['sourcerpm']
        )

        return package

    def collect_package_by_package(self, rpm_package: str) -> Package:
        immudb_info = self._extract_immudb_info_about_package(rpm_package=rpm_package)

    def collect_build_by_id(self, build_id: str) -> Build:
        pass

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

