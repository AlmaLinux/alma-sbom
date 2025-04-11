import os
from immudb_wrapper import ImmudbWrapper
from logging import getLogger

from alma_sbom.data import Package, PackageNevra

from .processor import DataProcessor, processor_factory

_logger = getLogger(__name__)

class ImmudbCollector:
    client: ImmudbWrapper
    processor: DataProcessor

    def __init__(
         self,
         username: str,
         password: str,
         database: str,
         immudb_address: str,
         public_key_file: str,
     ):
         self.client = ImmudbWrapper(
             username=username,
             password=password,
             database=database,
             immudb_address=immudb_address,
             public_key_file=public_key_file,
         )
         self.processor = None

    def collect_package_by_hash(self, hash: str) -> Package:
        immudb_info = self._extract_immudb_info_about_package(hash=hash)
        self.processor = processor_factory(immudb_info, hash)
        return self.processor.get_package()

    def collect_package_by_package(self, rpm_package: str) -> Package:
        immudb_info = self._extract_immudb_info_about_package(rpm_package=rpm_package)
        self.processor = processor_factory(immudb_info, hash=None)
        return self.processor.get_package()

    def _extract_immudb_info_about_package(self, hash: str = None, rpm_package: str = None) -> dict:
        response = {}
        if hash != None :
            response = self.client.authenticate(hash)
        elif rpm_package != None :
            response = self.client.authenticate_file(rpm_package)
        else:
            raise RuntimeError(
                'Unexpected situation has occurred. '
                'Required info to to extract immudb info has not been provided.'
            )

        result = response.get('value', {})
        result['timestamp'] = response.get('timestamp')
        return result

