import pytest

from cyclonedx.factory.license import LicenseFactory
from cyclonedx.model import HashAlgorithm, HashType
from cyclonedx.model.component import Property as CDXProperty
from cyclonedx.model.component import Component, ComponentType
from packageurl import PackageURL

from alma_sbom import constants
from alma_sbom.formats.cyclonedx.component import (
    component_from_package,
    component_from_build,
    component_from_iso,
)
from alma_sbom.type import Hash, PackageNevra, Licenses, Algorithms, SbomFileFormatType
from alma_sbom.data import Package, Build, Iso
from alma_sbom.data.attributes.property import (
    # Property,
    PackageProperties,
    BuildPropertiesForPackage,# as BuildProperties,
    BuildPropertiesForBuild,# as BuildProperties,
    GitSourceProperties,
    SBOMProperties,
)

lc_factory = LicenseFactory()


EXPECTED_PKG_COMPONENT = Component(
    name='bash',
    version='0:5.1.8-9.el9',
    type=ComponentType.LIBRARY,
    publisher=constants.ALMAOS_VENDOR,
    description='The GNU Bourne Again shell (Bash) is a shell or command language\ninterpreter that is compatible with the Bourne shell (sh). Bash\nincorporates useful features from the Korn shell (ksh) and the C shell\n(csh). Most sh scripts can be run by bash without modification.',
    hashes=[HashType(
        alg=HashAlgorithm(Algorithms.SHA_256.value),
        content='05dc1b806bd5456d40e3d7f882ead037aaf480c596e83fbfb6ab86be74a2d8d1',
    )],
    licenses=[lc_factory.make_from_string('GPLv3+')],
    purl=PackageURL.from_string('pkg:rpm/almalinux/bash@5.1.8-9.el9?arch=x86_64&distro=almalinux-9&upstream=bash-5.1.8-9.el9.src.rpm'),
    properties=[
        CDXProperty(name='almalinux:albs:build:ID', value='11363'),
        CDXProperty(name='almalinux:albs:build:author', value='eabdullin1 <55892454+eabdullin1@users.noreply.github.com>'),
        CDXProperty(name='almalinux:albs:build:packageType', value='rpm'),
        CDXProperty(name='almalinux:albs:build:source:gitCommit', value='https://git.almalinux.org/rpms/bash.git'),
        CDXProperty(name='almalinux:albs:build:source:gitCommitImmudbHash', value='4533026da95ca85fab57eafbc91c28a3a2dabd79'),
        CDXProperty(name='almalinux:albs:build:source:gitRef', value='imports/c9/bash-5.1.8-9.el9'),
        CDXProperty(name='almalinux:albs:build:source:gitURL', value='https://git.almalinux.org/rpms/bash.git'),
        CDXProperty(name='almalinux:albs:build:source:type', value='git'),
        CDXProperty(name='almalinux:albs:build:targetArch', value='x86_64'),
        CDXProperty(name='almalinux:package:arch', value='x86_64'),
        CDXProperty(name='almalinux:package:buildhost', value='x64-builder01.almalinux.org'),
        CDXProperty(name='almalinux:package:epoch', value='0'),
        CDXProperty(name='almalinux:package:release', value='9.el9'),
        CDXProperty(name='almalinux:package:sourcerpm', value='bash-5.1.8-9.el9.src.rpm'),
        CDXProperty(name='almalinux:package:timestamp', value='1714500330'),
        CDXProperty(name='almalinux:package:version', value='5.1.8'),
        CDXProperty(name='almalinux:sbom:immudbHash', value='05dc1b806bd5456d40e3d7f882ead037aaf480c596e83fbfb6ab86be74a2d8d1'),
    ],
    cpe='cpe:2.3:a:almalinux:bash:5.1.8-9.el9:*:*:*:*:*:*:*'
)

EXPECTED_BUILD_COMPONENT = Component(
    name='build-11363',
    author='test author',
    type=ComponentType.FRAMEWORK,
    properties=[
        CDXProperty(name='almalinux:albs:build:ID', value='11363'),
        CDXProperty(name='almalinux:albs:build:URL', value='https://build.almalinux.org/build/11363'),
        CDXProperty(name='almalinux:albs:build:timestamp', value='1714500330'),
    ],
)

EXPECTED_ISO_COMPONENT = Component(
    name='AlmaLinux 9.6 test ISO',
    type=ComponentType.OPERATING_SYSTEM,
)


@pytest.fixture
def package_instance() -> Package:
    return Package(
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
        licenses=Licenses(ids=[], expression='GPLv3+'),
        summary='The GNU Bourne Again shell',
        description='The GNU Bourne Again shell (Bash) is a shell or command language\ninterpreter that is compatible with the Bourne shell (sh). Bash\nincorporates useful features from the Korn shell (ksh) and the C shell\n(csh). Most sh scripts can be run by bash without modification.',
        package_properties=PackageProperties(
            epoch=0,
            version='5.1.8',
            release='9.el9',
            arch='x86_64',
            buildhost='x64-builder01.almalinux.org',
            sourcerpm='bash-5.1.8-9.el9.src.rpm',
            timestamp=1714500330,
        ),
        build_properties=BuildPropertiesForPackage(
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
def test_component_from_package(package_instance) -> None:
    assert component_from_package(package_instance) == EXPECTED_PKG_COMPONENT


### TODO: need to add packages !!!!!!!!!!!!!!!!!
@pytest.fixture
def build_instance() -> Build:
    return Build(
        build_id=11363,
        author='test author',
        packages=[],
        build_properties=BuildPropertiesForBuild(
            build_id=11363,
            build_url='https://build.almalinux.org/build/11363',
            timestamp=1714500330,
        ),
    )
def test_component_from_build(build_instance) -> None:
    assert component_from_build(build_instance) == EXPECTED_BUILD_COMPONENT


### TODO: need to add packages !!!!!!!!!!!!!!!!!
@pytest.fixture
def iso_instance() -> Iso:
    return Iso(
        releasever=9.6,
        image_type='test',
        packages=[],
    )
def test_component_from_iso(iso_instance) -> None:
    assert component_from_iso(iso_instance) == EXPECTED_ISO_COMPONENT
