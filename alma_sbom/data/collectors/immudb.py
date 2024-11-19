
import os
from immudb_wrapper import ImmudbWrapper

from alma_sbom.models.package import Package

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
        pass

