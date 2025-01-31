from abc import ABC, abstractmethod

from alma_sbom.type import Hash
from alma_sbom.data import Package, Build

class DataProcessor(ABC):
    immudb_info: dict
    immudb_metadata: dict
    hash: Hash

    def __init__(self, immudb_info: dict, immudb_metadata: dict, hash: Hash):
        self.immudb_info = immudb_info
        self.immudb_metadata = immudb_metadata
        self.hash = hash

    @abstractmethod
    def get_api_ver(self) -> str:
        pass

    @abstractmethod
    def get_package(self) -> Package:
        pass

