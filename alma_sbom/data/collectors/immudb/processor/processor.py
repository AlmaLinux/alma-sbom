from abc import ABC, abstractmethod

from alma_sbom.type import Hash
from alma_sbom.data import Package

class DataProcessor(ABC):
    immudb_info: dict
    immudb_metadata: dict
    hash: Hash

    def __init__(self, immudb_info: dict, immudb_metadata: dict, hash: Hash):
        self.immudb_info = immudb_info
        self.immudb_metadata = immudb_metadata
        self.hash = hash

    def _resolve_arch(self) -> str:
        """Return corrected arch for source RPMs.

        immudb metadata may store the builder machine arch (e.g. x86_64)
        instead of 'src' for SRPMs.  Use build_arch and the Name field
        as authoritative signals to fix this.
        """
        if self.immudb_metadata.get('build_arch') == 'src' or self.immudb_info.get('Name', '').endswith('.src.rpm'):
            return 'src'
        return self.immudb_metadata.get('arch')

    @abstractmethod
    def get_api_ver(self) -> str:
        pass

    @abstractmethod
    def get_package(self) -> Package:
        pass

