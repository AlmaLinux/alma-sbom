import os
import pytest

from alma_sbom.type import Hash, PackageNevra, Licenses, Algorithms
from alma_sbom.data.collectors import ImmudbCollector
from alma_sbom.data.attributes.property import (
    # Property,
    PackageProperties,
    BuildPropertiesForPackage as BuildProperties,
    GitSourceProperties,
    SBOMProperties,
)
from alma_sbom.data.models import Package
from alma_sbom.cli.config import CommonConfig

TESTED_HASH_VALUE = '05dc1b806bd5456d40e3d7f882ead037aaf480c596e83fbfb6ab86be74a2d8d1'
TESTED_HASH_VALUE_V1 = 'aeb7b7d638ebad749c8ef2ec7c8b699201e176101f129a49dcb5781158e95632'
TESTED_PACKAGE_NAME = 'bash-5.1.8-9.el9.x86_64.rpm'
TESTED_PACKAGE_PATH = os.path.dirname(os.path.dirname(__file__)) + f'/{TESTED_PACKAGE_NAME}'

EXPECTED_PACKAGE = Package(
    package_nevra=PackageNevra( # 0:bash-5.1.8-9.el9.x86_64
        epoch = 0,
        name = 'bash',
        version = '5.1.8',
        release = '9.el9',
        arch = 'x86_64',
    ),
    source_rpm='bash-5.1.8-9.el9.src.rpm',
    package_timestamp=1714500330,
    hashs=[Hash(
        value='05dc1b806bd5456d40e3d7f882ead037aaf480c596e83fbfb6ab86be74a2d8d1',
        algorithm=Algorithms.SHA_256,
    )],
    # licenses=Licenses(ids=[], expression='GPLv3+'),
    # summary='The GNU Bourne Again shell',
    # description='The GNU Bourne Again shell (Bash) is a shell or command language\ninterpreter that is compatible with the Bourne shell (sh). Bash\nincorporates useful features from the Korn shell (ksh) and the C shell\n(csh). Most sh scripts can be run by bash without modification.',
    package_properties=PackageProperties(
        epoch=0,
        version='5.1.8',
        release='9.el9',
        arch='x86_64',
        buildhost='x64-builder01.almalinux.org',
        sourcerpm='bash-5.1.8-9.el9.src.rpm',
        timestamp=1714500330,
    ),
    build_properties=BuildProperties(
        build_id=11363,
        build_url=None,
        author='eabdullin1 <55892454+eabdullin1@users.noreply.github.com>',
        package_type='rpm',
        target_arch='x86_64',
        source=GitSourceProperties(
            # source_type='git',
            git_url='https://git.almalinux.org/rpms/bash.git',
            git_commit='https://git.almalinux.org/rpms/bash.git',
            git_ref='imports/c9/bash-5.1.8-9.el9',
            git_commit_immudb_hash='4533026da95ca85fab57eafbc91c28a3a2dabd79',
        ),
    ),
    sbom_properties=SBOMProperties(
        immudb_hash='05dc1b806bd5456d40e3d7f882ead037aaf480c596e83fbfb6ab86be74a2d8d1',
    ),
)


@pytest.fixture
def immudb_collector_instance() -> ImmudbCollector:
    return ImmudbCollector(
        username=CommonConfig.DEF_IMMUDB_USERNAME,
        password=CommonConfig.DEF_IMMUDB_PASSWORD,
        database=CommonConfig.DEF_IMMUDB_DATABASE,
        immudb_address=CommonConfig.DEF_IMMUDB_ADDRESS,
        public_key_file=CommonConfig.DEF_IMMUDB_PUBLIC_KEY_FILE,
    )


def test_collect_package_by_hash(immudb_collector_instance: ImmudbCollector) -> None:
    assert immudb_collector_instance.collect_package_by_hash(TESTED_HASH_VALUE) == EXPECTED_PACKAGE

    # assert immudb_collector_instance._extract_immudb_info_about_package(hash=TESTED_HASH_VALUE_V1) == None
    # assert immudb_collector_instance.collect_package_by_hash(TESTED_HASH_VALUE_V1) == None


def test_collect_package_by_package(immudb_collector_instance: ImmudbCollector) -> None:
    assert immudb_collector_instance.collect_package_by_package(TESTED_PACKAGE_PATH) == EXPECTED_PACKAGE


# def test_______immudb_info(immudb_collector_instance: ImmudbCollector) -> None:
#     # def _extract_immudb_info_about_package(self, hash: str = None, rpm_package: str = None) -> dict:
#     immudb_info = immudb_collector_instance._extract_immudb_info_about_package(hash=TESTED_HASH_VALUE)
#     assert immudb_info == None

