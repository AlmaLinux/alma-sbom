import pytest

from alma_sbom.type import Hash, Algorithms
from alma_sbom.data import Package, PackageNevra
from alma_sbom.data.attributes.property import (
    PackageProperties,
    BuildSourceProperties,
    GitSourceProperties,
    SrpmSourceProperties,
    BuildPropertiesForPackage as BuildProperties,
    SBOMProperties,
)
from alma_sbom.data.collectors.immudb.processor.apiver01 import DataProcessor01


TESTED_IMMUDB_INFO_V1 = {
    'Name': 'bash-4.4.20-4.el8_6.x86_64.rpm',
    'Kind': 'file',
    'Size': 1621188,
    'Hash': 'aeb7b7d638ebad749c8ef2ec7c8b699201e176101f129a49dcb5781158e95632',
    'Metadata': {
        'alma_commit_sbom_hash': '7893d8abfaebb88e3910b2f9b7a06497bee84e8e01b00f316097df6f70f976de',
        'build_arch': 'x86_64',
        'build_host': 'https://build.almalinux.org/api/v1/',
        'build_id': '3823',
        'built_by': 'andrewlukoshko <andrew.lukoshko@gmail.com>',
        'git_commit': '5cd0d67a640d79bbbbd09ed867f699136b4db8b6',
        'git_ref': 'imports/c8/bash-4.4.20-4.el8_6',
        'git_url': 'https://git.almalinux.org/rpms/bash.git',
        'sbom_api': '0.1',
        'source_type': 'git',
        'unsigned_hash': 'b59d13c0413084a6ee8cddf94038e7b7f772da2fdbcd57cc5101a52d1dc4d23f'
    },
    'Signer': 'sbom_signer_almalinux',
    'Original_timestamp': '0001-01-01T00:00:00Z',
    'timestamp': 1695042331
}

EXPECTED_PACKAGE = Package(
    # package_nevra=bash-4.4.20-4.el8_6.x86_64,
    package_nevra=PackageNevra( # bash-4.4.20-4.el8_6.x86_64
        epoch = None,
        name = 'bash',
        version = '4.4.20',
        release = '4.el8_6',
        arch = 'x86_64',
    ),
    source_rpm=None,
    package_timestamp=1695042331,
    # hashs=[Hash(
    #     value='aeb7b7d638ebad749c8ef2ec7c8b699201e176101f129a49dcb5781158e95632',
    #     algorithm=Algorithms.SHA_256,
    # )],
    hashs=[None],
    licenses=None,
    summary=None,
    description=None,
    package_properties=PackageProperties(
        epoch=None,
        version='4.4.20',
        release='4.el8_6',
        arch='x86_64',
        buildhost='https://build.almalinux.org/api/v1/',
        sourcerpm=None,
        timestamp=1695042331
    ),
    build_properties=BuildProperties(
        build_id='3823',
        build_url=None,
        author='andrewlukoshko <andrew.lukoshko@gmail.com>',
        package_type='rpm',
        target_arch='x86_64',
        source=GitSourceProperties(
            # source_type='git',
            git_url='https://git.almalinux.org/rpms/bash.git',
            git_commit='https://git.almalinux.org/rpms/bash.git',
            git_ref='imports/c8/bash-4.4.20-4.el8_6',
            git_commit_immudb_hash='7893d8abfaebb88e3910b2f9b7a06497bee84e8e01b00f316097df6f70f976de'
        )
    ),
    sbom_properties=SBOMProperties(
        immudb_hash='aeb7b7d638ebad749c8ef2ec7c8b699201e176101f129a49dcb5781158e95632'
    )
)


@pytest.fixture
def data_processor_01_instance() -> DataProcessor01:
    return DataProcessor01(
        immudb_info=TESTED_IMMUDB_INFO_V1,
        immudb_metadata=TESTED_IMMUDB_INFO_V1['Metadata'],
        hash=None,
    )


def test_get_api_ver(data_processor_01_instance: DataProcessor01) -> None:
    assert data_processor_01_instance.get_api_ver() == '0.1'


def test_get_package(data_processor_01_instance: DataProcessor01) -> None:
    assert data_processor_01_instance.get_package() == EXPECTED_PACKAGE

