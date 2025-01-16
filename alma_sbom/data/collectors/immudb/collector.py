import os
from immudb_wrapper import ImmudbWrapper
from logging import getLogger

from alma_sbom.data.models.package import Hash, Algorithms
from alma_sbom.data import Package, Build, PackageNevra

from .processor import DataProcessor, processor_factory


_logger = getLogger(__name__)

class ImmudbCollector:
    client: ImmudbWrapper
    processor: DataProcessor

    ### TODO:
    # This method of setting default values for arguments will fail
    # if both the specified argument and the environment variable are None.
    # This should be changed to a method that sets default values at finally.
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
         self.processor = None

    def collect_package_by_hash(self, hash: str) -> Package:
        immudb_info = self._extract_immudb_info_about_package(hash=hash)
        self.processor = processor_factory(immudb_info, hash)
        return self.processor.get_package()

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

