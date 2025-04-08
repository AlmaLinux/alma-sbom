import configparser
import io
import os
import pycdlib
import tempfile
from typing import ClassVar, Iterator

from alma_sbom.data import Iso

class IsoCollector:
    PATH_TO_TREEINFO: ClassVar[str] = '/.treeinfo'
    DVD_REPO_LIST: ClassVar[list[str]] = ['AppStream', 'BaseOS']
    MINIMAL_REPO_LIST: ClassVar[list[str]] = ['Minimal']

    iso: pycdlib.PyCdlib
    config: configparser.ConfigParser
    memfd_path: int
    repositories_info: dict

    def __init__(self):
        self.iso = pycdlib.PyCdlib()
        self.config = configparser.ConfigParser()
        memfd = os.memfd_create('package', flags=0)
        self.memfd_path = f'/proc/self/fd/{memfd}'

    def collect_iso_by_file(self, iso_image: str) -> Iso: ### Path にすべきかも
        self._read_iso(iso_image)
        self._check_almalinux_iso()

        self.repositories_info = self._get_repositories_info()

        releasever = self._get_releasever()
        image_type = self._get_image_type(self.repositories_info)

        return Iso(
            releasever,
            image_type,
            packages=[],
        )

    def get_fd_path(self) -> int:
        return self.memfd_path

    def iter_packages(self) -> Iterator[None]:
        for variant_packages_repo in self.repositories_info.values():
            for _ in self._iter_packages_per_repo(variant_packages_repo):
                yield

    def _read_iso(self, iso_image: str) -> None:
        self.iso.open(iso_image)
        with tempfile.NamedTemporaryFile(delete=True) as tmp:
            self.iso.get_file_from_iso(local_path=tmp.name, rr_path=self.PATH_TO_TREEINFO)
            self.config.read(tmp.name)

    def _check_almalinux_iso(self) -> None:
        if 'general' in self.config and 'family' in self.config['general']:
            if self.config['general']['family'] != 'AlmaLinux':
                raise ValueError(f"alma-sbom only can make ISO SBOM for AlmaLinux ISO image. This is ISO image of {self.config['general']['family']}")
        else:
            raise KeyError(f'Can not detect OS name.')

    def _get_repositories_info(self) -> dict:
        variants = []
        if 'general' in self.config and 'variants' in self.config['general']:
            variants = self.config['general']['variants'].split(',')
        elif 'tree' in self.config and 'variants' in self.config['tree']:
            variants = self.config['tree']['variants'].split(',')
        else:
            raise KeyError(f'Can not get repositories(variants) info.')
        variant_packages = {}
        for variant in variants:
            section_name = f'variant-{variant}'
            if section_name in self.config and 'packages' in self.config[section_name]:
                variant_packages[variant] = self.config[section_name]['packages']
            else:
                raise RuntimeError('Unexpected situation has occurred')
        return variant_packages

    def _get_releasever(self) -> str:
        if 'general' in self.config and 'version' in self.config['general']:
            return self.config['general']['version']
        raise KeyError('Cat not detect OS version.')

    def _get_image_type(self, repositories_info: dict) -> str:
        repositories_list = list(repositories_info.keys())
        if repositories_list == self.DVD_REPO_LIST:
            return 'DVD'
        elif repositories_list == self.MINIMAL_REPO_LIST:
            return 'Minimal'
        raise KeyError('Cat not detect image type.')

    def _iter_packages_per_repo(self, variant_packages_repo: str) -> Iterator[None]:
        variant_path = os.path.join('/', variant_packages_repo)
        variant_entry = self.iso.get_record(iso_path=variant_path)
        for child in variant_entry.children:
            pkg_name = child.rock_ridge.name().decode('utf8')
            if pkg_name.endswith('.rpm'):
                full_rr_path = os.path.join(variant_path, pkg_name)
                self.iso.get_file_from_iso(
                    local_path=self.memfd_path,
                    rr_path=full_rr_path,
                )
                yield

