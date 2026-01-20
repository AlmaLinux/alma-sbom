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
from alma_sbom.data.collectors.immudb.processor.apiver02 import DataProcessor02


TESTED_IMMUDB_INFO_V2 = {
    'Name': 'bash-5.1.8-9.el9.x86_64.rpm',
    'Kind': 'file',
    'Size': '1.66 MB',
    'Hash': '05dc1b806bd5456d40e3d7f882ead037aaf480c596e83fbfb6ab86be74a2d8d1',
    'Signer': 'sbom_signer_almalinux',
    'Metadata': {
        'sbom_api_ver': '0.2',
        'unsigned_hash': 'c4def308974a4a3fad42c37d1e85da789be4966104473f39adc569f1dc8a271e',
        'build_id': 11363,
        'build_host': 'x64-builder01.almalinux.org',
        'build_arch': 'x86_64',
        'built_by': 'eabdullin1 <55892454+eabdullin1@users.noreply.github.com>',
        'alma_commit_sbom_hash': '4533026da95ca85fab57eafbc91c28a3a2dabd79',
        'source_type': 'git',
        'git_url': 'https://git.almalinux.org/rpms/bash.git',
        'git_ref': 'imports/c9/bash-5.1.8-9.el9',
        'git_commit': '4533026da95ca85fab57eafbc91c28a3a2dabd79',
        'name': 'bash',
        'epoch': None,
        'version': '5.1.8',
        'release': '9.el9',
        'arch': 'x86_64',
        'sourcerpm': 'bash-5.1.8-9.el9.src.rpm',
    },
    'timestamp': 1714500330,
}

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
    hashs=[None],
    licenses=None,
    summary=None,
    description=None,
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
def data_processor_02_instance() -> DataProcessor02:
    return DataProcessor02(
        immudb_info=TESTED_IMMUDB_INFO_V2,
        immudb_metadata=TESTED_IMMUDB_INFO_V2['Metadata'],
        hash=None,
    )


def test_get_api_ver(data_processor_02_instance: DataProcessor02) -> None:
    assert data_processor_02_instance.get_api_ver() == '0.2'


def test_get_package(data_processor_02_instance: DataProcessor02) -> None:
    assert data_processor_02_instance.get_package() == EXPECTED_PACKAGE
